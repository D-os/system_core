/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG INCREMENTAL

#include "incremental_server.h"

#include <android-base/endian.h>
#include <android-base/strings.h>
#include <inttypes.h>
#include <lz4.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <array>
#include <deque>
#include <fstream>
#include <thread>
#include <type_traits>
#include <unordered_set>

#include "adb.h"
#include "adb_io.h"
#include "adb_trace.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "sysdeps.h"

namespace incremental {

static constexpr int kBlockSize = 4096;
static constexpr int kCompressedSizeMax = kBlockSize * 0.95;
static constexpr short kCompressionNone = 0;
static constexpr short kCompressionLZ4 = 1;
static constexpr int kCompressBound = std::max(kBlockSize, LZ4_COMPRESSBOUND(kBlockSize));
static constexpr auto kReadBufferSize = 128 * 1024;
static constexpr int kPollTimeoutMillis = 300000;  // 5 minutes

using BlockSize = int16_t;
using FileId = int16_t;
using BlockIdx = int32_t;
using NumBlocks = int32_t;
using CompressionType = int16_t;
using RequestType = int16_t;
using ChunkHeader = int32_t;
using MagicType = uint32_t;

static constexpr MagicType INCR = 0x494e4352;  // LE INCR

static constexpr RequestType SERVING_COMPLETE = 0;
static constexpr RequestType BLOCK_MISSING = 1;
static constexpr RequestType PREFETCH = 2;
static constexpr RequestType DESTROY = 3;

static constexpr inline int64_t roundDownToBlockOffset(int64_t val) {
    return val & ~(kBlockSize - 1);
}

static constexpr inline int64_t roundUpToBlockOffset(int64_t val) {
    return roundDownToBlockOffset(val + kBlockSize - 1);
}

static constexpr inline NumBlocks numBytesToNumBlocks(int64_t bytes) {
    return roundUpToBlockOffset(bytes) / kBlockSize;
}

static constexpr inline off64_t blockIndexToOffset(BlockIdx blockIdx) {
    return static_cast<off64_t>(blockIdx) * kBlockSize;
}

template <typename T>
static inline constexpr T toBigEndian(T t) {
    using unsigned_type = std::make_unsigned_t<T>;
    if constexpr (std::is_same_v<T, int16_t>) {
        return htobe16(static_cast<unsigned_type>(t));
    } else if constexpr (std::is_same_v<T, int32_t>) {
        return htobe32(static_cast<unsigned_type>(t));
    } else if constexpr (std::is_same_v<T, int64_t>) {
        return htobe64(static_cast<unsigned_type>(t));
    } else {
        return t;
    }
}

template <typename T>
static inline constexpr T readBigEndian(void* data) {
    using unsigned_type = std::make_unsigned_t<T>;
    if constexpr (std::is_same_v<T, int16_t>) {
        return static_cast<T>(be16toh(*reinterpret_cast<unsigned_type*>(data)));
    } else if constexpr (std::is_same_v<T, int32_t>) {
        return static_cast<T>(be32toh(*reinterpret_cast<unsigned_type*>(data)));
    } else if constexpr (std::is_same_v<T, int64_t>) {
        return static_cast<T>(be64toh(*reinterpret_cast<unsigned_type*>(data)));
    } else {
        return T();
    }
}

// Received from device
// !Does not include magic!
struct RequestCommand {
    RequestType request_type;  // 2 bytes
    FileId file_id;            // 2 bytes
    union {
        BlockIdx block_idx;
        NumBlocks num_blocks;
    };  // 4 bytes
} __attribute__((packed));

// Placed before actual data bytes of each block
struct ResponseHeader {
    FileId file_id;                    // 2 bytes
    CompressionType compression_type;  // 2 bytes
    BlockIdx block_idx;                // 4 bytes
    BlockSize block_size;              // 2 bytes
} __attribute__((packed));

// Holds streaming state for a file
class File {
  public:
    // Plain file
    File(const char* filepath, FileId id, int64_t size, unique_fd fd) : File(filepath, id, size) {
        this->fd_ = std::move(fd);
    }
    int64_t ReadBlock(BlockIdx block_idx, void* buf, bool* is_zip_compressed,
                      std::string* error) const {
        char* buf_ptr = static_cast<char*>(buf);
        int64_t bytes_read = -1;
        const off64_t offsetStart = blockIndexToOffset(block_idx);
        bytes_read = adb_pread(fd_, &buf_ptr[sizeof(ResponseHeader)], kBlockSize, offsetStart);
        return bytes_read;
    }

    const unique_fd& RawFd() const { return fd_; }

    std::vector<bool> sentBlocks;
    NumBlocks sentBlocksCount = 0;

    const char* const filepath;
    const FileId id;
    const int64_t size;

  private:
    File(const char* filepath, FileId id, int64_t size) : filepath(filepath), id(id), size(size) {
        sentBlocks.resize(numBytesToNumBlocks(size));
    }
    unique_fd fd_;
};

class IncrementalServer {
  public:
    IncrementalServer(unique_fd adb_fd, unique_fd output_fd, std::vector<File> files)
        : adb_fd_(std::move(adb_fd)), output_fd_(std::move(output_fd)), files_(std::move(files)) {
        buffer_.reserve(kReadBufferSize);
    }

    bool Serve();

  private:
    struct PrefetchState {
        const File* file;
        BlockIdx overallIndex = 0;
        BlockIdx overallEnd = 0;

        PrefetchState(const File& f) : file(&f), overallEnd((BlockIdx)f.sentBlocks.size()) {}
        PrefetchState(const File& f, BlockIdx start, int count)
            : file(&f),
              overallIndex(start),
              overallEnd(std::min<BlockIdx>(start + count, f.sentBlocks.size())) {}

        bool done() const { return overallIndex >= overallEnd; }
    };

    bool SkipToRequest(void* buffer, size_t* size, bool blocking);
    std::optional<RequestCommand> ReadRequest(bool blocking);

    void erase_buffer_head(int count) { buffer_.erase(buffer_.begin(), buffer_.begin() + count); }

    enum class SendResult { Sent, Skipped, Error };
    SendResult SendBlock(FileId fileId, BlockIdx blockIdx, bool flush = false);
    bool SendDone();
    void RunPrefetching();

    void Send(const void* data, size_t size, bool flush);
    void Flush();
    using TimePoint = decltype(std::chrono::high_resolution_clock::now());
    bool ServingComplete(std::optional<TimePoint> startTime, int missesCount, int missesSent);

    unique_fd const adb_fd_;
    unique_fd const output_fd_;
    std::vector<File> files_;

    // Incoming data buffer.
    std::vector<char> buffer_;

    std::deque<PrefetchState> prefetches_;
    int compressed_ = 0, uncompressed_ = 0;
    long long sentSize_ = 0;

    std::vector<char> pendingBlocks_;

    // True when client notifies that all the data has been received
    bool servingComplete_;
};

bool IncrementalServer::SkipToRequest(void* buffer, size_t* size, bool blocking) {
    while (true) {
        // Looking for INCR magic.
        bool magic_found = false;
        int bcur = 0;
        int bsize = buffer_.size();
        for (bcur = 0; bcur + 4 < bsize; ++bcur) {
            uint32_t magic = be32toh(*(uint32_t*)(buffer_.data() + bcur));
            if (magic == INCR) {
                magic_found = true;
                break;
            }
        }

        if (bcur > 0) {
            // output the rest.
            WriteFdExactly(output_fd_, buffer_.data(), bcur);
            erase_buffer_head(bcur);
        }

        if (magic_found && buffer_.size() >= *size + sizeof(INCR)) {
            // fine, return
            memcpy(buffer, buffer_.data() + sizeof(INCR), *size);
            erase_buffer_head(*size + sizeof(INCR));
            return true;
        }

        adb_pollfd pfd = {adb_fd_.get(), POLLIN, 0};
        auto res = adb_poll(&pfd, 1, blocking ? kPollTimeoutMillis : 0);

        if (res != 1) {
            WriteFdExactly(output_fd_, buffer_.data(), buffer_.size());
            if (res < 0) {
                D("Failed to poll: %s\n", strerror(errno));
                return false;
            }
            if (blocking) {
                fprintf(stderr, "Timed out waiting for data from device.\n");
            }
            if (blocking && servingComplete_) {
                // timeout waiting from client. Serving is complete, so quit.
                return false;
            }
            *size = 0;
            return true;
        }

        bsize = buffer_.size();
        buffer_.resize(kReadBufferSize);
        int r = adb_read(adb_fd_, buffer_.data() + bsize, kReadBufferSize - bsize);
        if (r > 0) {
            buffer_.resize(bsize + r);
            continue;
        }

        D("Failed to read from fd %d: %d. Exit\n", adb_fd_.get(), errno);
        break;
    }
    // socket is closed. print remaining messages
    WriteFdExactly(output_fd_, buffer_.data(), buffer_.size());
    return false;
}

std::optional<RequestCommand> IncrementalServer::ReadRequest(bool blocking) {
    uint8_t commandBuf[sizeof(RequestCommand)];
    auto size = sizeof(commandBuf);
    if (!SkipToRequest(&commandBuf, &size, blocking)) {
        return {{DESTROY}};
    }
    if (size < sizeof(RequestCommand)) {
        return {};
    }
    RequestCommand request;
    request.request_type = readBigEndian<RequestType>(&commandBuf[0]);
    request.file_id = readBigEndian<FileId>(&commandBuf[2]);
    request.block_idx = readBigEndian<BlockIdx>(&commandBuf[4]);
    return request;
}

auto IncrementalServer::SendBlock(FileId fileId, BlockIdx blockIdx, bool flush) -> SendResult {
    auto& file = files_[fileId];
    if (blockIdx >= static_cast<long>(file.sentBlocks.size())) {
        fprintf(stderr, "Failed to read file %s at block %" PRId32 " (past end).\n", file.filepath,
                blockIdx);
        return SendResult::Error;
    }
    if (file.sentBlocks[blockIdx]) {
        return SendResult::Skipped;
    }
    std::string error;
    char raw[sizeof(ResponseHeader) + kBlockSize];
    bool isZipCompressed = false;
    const int64_t bytesRead = file.ReadBlock(blockIdx, &raw, &isZipCompressed, &error);
    if (bytesRead < 0) {
        fprintf(stderr, "Failed to get data for %s at blockIdx=%d (%s).\n", file.filepath, blockIdx,
                error.c_str());
        return SendResult::Error;
    }

    ResponseHeader* header = nullptr;
    char data[sizeof(ResponseHeader) + kCompressBound];
    char* compressed = data + sizeof(*header);
    int16_t compressedSize = 0;
    if (!isZipCompressed) {
        compressedSize =
                LZ4_compress_default(raw + sizeof(*header), compressed, bytesRead, kCompressBound);
    }
    int16_t blockSize;
    if (compressedSize > 0 && compressedSize < kCompressedSizeMax) {
        ++compressed_;
        blockSize = compressedSize;
        header = reinterpret_cast<ResponseHeader*>(data);
        header->compression_type = toBigEndian(kCompressionLZ4);
    } else {
        ++uncompressed_;
        blockSize = bytesRead;
        header = reinterpret_cast<ResponseHeader*>(raw);
        header->compression_type = toBigEndian(kCompressionNone);
    }

    header->file_id = toBigEndian(fileId);
    header->block_size = toBigEndian(blockSize);
    header->block_idx = toBigEndian(blockIdx);

    file.sentBlocks[blockIdx] = true;
    file.sentBlocksCount += 1;
    Send(header, sizeof(*header) + blockSize, flush);
    return SendResult::Sent;
}

bool IncrementalServer::SendDone() {
    ResponseHeader header;
    header.file_id = -1;
    header.compression_type = 0;
    header.block_idx = 0;
    header.block_size = 0;
    Send(&header, sizeof(header), true);
    return true;
}

void IncrementalServer::RunPrefetching() {
    constexpr auto kPrefetchBlocksPerIteration = 128;

    int blocksToSend = kPrefetchBlocksPerIteration;
    while (!prefetches_.empty() && blocksToSend > 0) {
        auto& prefetch = prefetches_.front();
        const auto& file = *prefetch.file;
        for (auto& i = prefetch.overallIndex; blocksToSend > 0 && i < prefetch.overallEnd; ++i) {
            if (auto res = SendBlock(file.id, i); res == SendResult::Sent) {
                --blocksToSend;
            } else if (res == SendResult::Error) {
                fprintf(stderr, "Failed to send block %" PRId32 "\n", i);
            }
        }
        if (prefetch.done()) {
            prefetches_.pop_front();
        }
    }
}

void IncrementalServer::Send(const void* data, size_t size, bool flush) {
    constexpr auto kChunkFlushSize = 31 * kBlockSize;

    if (pendingBlocks_.empty()) {
        pendingBlocks_.resize(sizeof(ChunkHeader));
    }
    pendingBlocks_.insert(pendingBlocks_.end(), static_cast<const char*>(data),
                          static_cast<const char*>(data) + size);
    if (flush || pendingBlocks_.size() > kChunkFlushSize) {
        Flush();
    }
}

void IncrementalServer::Flush() {
    if (pendingBlocks_.empty()) {
        return;
    }

    *(ChunkHeader*)pendingBlocks_.data() =
            toBigEndian<int32_t>(pendingBlocks_.size() - sizeof(ChunkHeader));
    if (!WriteFdExactly(adb_fd_, pendingBlocks_.data(), pendingBlocks_.size())) {
        fprintf(stderr, "Failed to write %d bytes\n", int(pendingBlocks_.size()));
    }
    sentSize_ += pendingBlocks_.size();
    pendingBlocks_.clear();
}

bool IncrementalServer::ServingComplete(std::optional<TimePoint> startTime, int missesCount,
                                        int missesSent) {
    servingComplete_ = true;
    using namespace std::chrono;
    auto endTime = high_resolution_clock::now();
    D("Streaming completed.\n"
      "Misses: %d, of those unique: %d; sent compressed: %d, uncompressed: "
      "%d, mb: %.3f\n"
      "Total time taken: %.3fms\n",
      missesCount, missesSent, compressed_, uncompressed_, sentSize_ / 1024.0 / 1024.0,
      duration_cast<microseconds>(endTime - (startTime ? *startTime : endTime)).count() / 1000.0);
    return true;
}

bool IncrementalServer::Serve() {
    // Initial handshake to verify connection is still alive
    if (!SendOkay(adb_fd_)) {
        fprintf(stderr, "Connection is dead. Abort.\n");
        return false;
    }

    std::unordered_set<FileId> prefetchedFiles;
    bool doneSent = false;
    int missesCount = 0;
    int missesSent = 0;

    using namespace std::chrono;
    std::optional<TimePoint> startTime;

    while (true) {
        if (!doneSent && prefetches_.empty() &&
            std::all_of(files_.begin(), files_.end(), [](const File& f) {
                return f.sentBlocksCount == NumBlocks(f.sentBlocks.size());
            })) {
            fprintf(stderr, "All files should be loaded. Notifying the device.\n");
            SendDone();
            doneSent = true;
        }

        const bool blocking = prefetches_.empty();
        if (blocking) {
            // We've no idea how long the blocking call is, so let's flush whatever is still unsent.
            Flush();
        }
        auto request = ReadRequest(blocking);

        if (!startTime) {
            startTime = high_resolution_clock::now();
        }

        if (request) {
            FileId fileId = request->file_id;
            BlockIdx blockIdx = request->block_idx;

            switch (request->request_type) {
                case DESTROY: {
                    // Stop everything.
                    return true;
                }
                case SERVING_COMPLETE: {
                    // Not stopping the server here.
                    ServingComplete(startTime, missesCount, missesSent);
                    break;
                }
                case BLOCK_MISSING: {
                    ++missesCount;
                    // Sends one single block ASAP.
                    if (fileId < 0 || fileId >= (FileId)files_.size() || blockIdx < 0 ||
                        blockIdx >= (BlockIdx)files_[fileId].sentBlocks.size()) {
                        fprintf(stderr,
                                "Received invalid data request for file_id %" PRId16
                                " block_idx %" PRId32 ".\n",
                                fileId, blockIdx);
                        break;
                    }
                    // fprintf(stderr, "\treading file %d block %04d\n", (int)fileId,
                    // (int)blockIdx);
                    if (auto res = SendBlock(fileId, blockIdx, true); res == SendResult::Error) {
                        fprintf(stderr, "Failed to send block %" PRId32 ".\n", blockIdx);
                    } else if (res == SendResult::Sent) {
                        ++missesSent;
                        // Make sure we send more pages from this place onward, in case if the OS is
                        // reading a bigger block.
                        prefetches_.emplace_front(files_[fileId], blockIdx + 1, 7);
                    }
                    break;
                }
                case PREFETCH: {
                    // Start prefetching for a file
                    if (fileId < 0) {
                        fprintf(stderr,
                                "Received invalid prefetch request for file_id %" PRId16 "\n",
                                fileId);
                        break;
                    }
                    if (!prefetchedFiles.insert(fileId).second) {
                        fprintf(stderr,
                                "Received duplicate prefetch request for file_id %" PRId16 "\n",
                                fileId);
                        break;
                    }
                    D("Received prefetch request for file_id %" PRId16 ".\n", fileId);
                    prefetches_.emplace_back(files_[fileId]);
                    break;
                }
                default:
                    fprintf(stderr, "Invalid request %" PRId16 ",%" PRId16 ",%" PRId32 ".\n",
                            request->request_type, fileId, blockIdx);
                    break;
            }
        }

        RunPrefetching();
    }
}

bool serve(int connection_fd, int output_fd, int argc, const char** argv) {
    auto connection_ufd = unique_fd(connection_fd);
    auto output_ufd = unique_fd(output_fd);
    if (argc <= 0) {
        error_exit("inc-server: must specify at least one file.");
    }

    std::vector<File> files;
    files.reserve(argc);
    for (int i = 0; i < argc; ++i) {
        auto filepath = argv[i];

        struct stat st;
        if (stat(filepath, &st)) {
            fprintf(stderr, "Failed to stat input file %s. Abort.\n", filepath);
            return {};
        }

        unique_fd fd(adb_open(filepath, O_RDONLY));
        if (fd < 0) {
            error_exit("inc-server: failed to open file '%s'.", filepath);
        }
        files.emplace_back(filepath, i, st.st_size, std::move(fd));
    }

    IncrementalServer server(std::move(connection_ufd), std::move(output_ufd), std::move(files));
    printf("Serving...\n");
    fclose(stdin);
    fclose(stdout);
    return server.Serve();
}

}  // namespace incremental
