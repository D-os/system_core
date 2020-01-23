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

// LOG_TAG must be unset for android-base's logging to use a default tag.
#undef LOG_TAG

#include <stdlib.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/log.h>

#include <gtest/gtest.h>

TEST(liblog_default_tag, no_default_tag_libbase_write_first) {
  using namespace android::base;
  bool message_seen = false;
  std::string expected_tag = "";
  SetLogger([&](LogId, LogSeverity, const char* tag, const char*, unsigned int, const char*) {
    message_seen = true;
    EXPECT_EQ(expected_tag, tag);
  });

  expected_tag = getprogname();
  LOG(WARNING) << "message";
  EXPECT_TRUE(message_seen);
  message_seen = false;

  __android_log_buf_write(LOG_ID_MAIN, ANDROID_LOG_WARN, nullptr, "message");
  EXPECT_TRUE(message_seen);
}

TEST(liblog_default_tag, no_default_tag_liblog_write_first) {
  using namespace android::base;
  bool message_seen = false;
  std::string expected_tag = "";
  SetLogger([&](LogId, LogSeverity, const char* tag, const char*, unsigned int, const char*) {
    message_seen = true;
    EXPECT_EQ(expected_tag, tag);
  });

  expected_tag = getprogname();
  __android_log_buf_write(LOG_ID_MAIN, ANDROID_LOG_WARN, nullptr, "message");
  EXPECT_TRUE(message_seen);
  message_seen = false;

  LOG(WARNING) << "message";
  EXPECT_TRUE(message_seen);
}

TEST(liblog_default_tag, libbase_sets_default_tag) {
  using namespace android::base;
  bool message_seen = false;
  std::string expected_tag = "libbase_test_tag";
  SetLogger([&](LogId, LogSeverity, const char* tag, const char*, unsigned int, const char*) {
    message_seen = true;
    EXPECT_EQ(expected_tag, tag);
  });
  SetDefaultTag(expected_tag);

  __android_log_buf_write(LOG_ID_MAIN, ANDROID_LOG_WARN, nullptr, "message");
  EXPECT_TRUE(message_seen);
  message_seen = false;

  LOG(WARNING) << "message";
  EXPECT_TRUE(message_seen);
}

TEST(liblog_default_tag, liblog_sets_default_tag) {
  using namespace android::base;
  bool message_seen = false;
  std::string expected_tag = "liblog_test_tag";
  SetLogger([&](LogId, LogSeverity, const char* tag, const char*, unsigned int, const char*) {
    message_seen = true;
    EXPECT_EQ(expected_tag, tag);
  });
  __android_log_set_default_tag(expected_tag.c_str());

  __android_log_buf_write(LOG_ID_MAIN, ANDROID_LOG_WARN, nullptr, "message");
  EXPECT_TRUE(message_seen);
  message_seen = false;

  LOG(WARNING) << "message";
  EXPECT_TRUE(message_seen);
}