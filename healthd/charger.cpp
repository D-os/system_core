/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <android-base/logging.h>
#include <charger.sysprop.h>

#include "healthd_mode_charger_hidl.h"
#include "healthd_mode_charger_nops.h"

#ifndef CHARGER_FORCE_NO_UI
#define CHARGER_FORCE_NO_UI 0
#endif

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);
    if (CHARGER_FORCE_NO_UI || android::sysprop::ChargerProperties::no_ui().value_or(false)) {
        return healthd_charger_nops(argc, argv);
    } else {
        return healthd_charger_main(argc, argv);
    }
}
