<?php
// Copyright (c) Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

/**
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

defined('MOODLE_INTERNAL') || die();

// Register observers for specific events we want to track
$observers = [
    // Observer for course module created events
    [
        'eventname' => '\core\event\course_module_created',
        'callback'  => '\local_awsevents\observer::process_event',
    ],
];