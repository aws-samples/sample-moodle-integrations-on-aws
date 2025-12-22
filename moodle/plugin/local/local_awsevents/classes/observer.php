<?php
// Copyright (c) Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

/**
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

namespace local_awsevents;

defined('MOODLE_INTERNAL') || die();

/**
 * Event observer class
 */
class observer {
    /**
     * Process events and forward to AWS EventBridge
     *
     * @param \core\event\base $event The event being triggered
     */
    public static function process_event(\core\event\base $event) {
        global $CFG;
        $debug = !empty($CFG->local_awsevents_debug);

        try {
            if ($debug) {
                debugging('Processing event: ' . $event->eventname . ' (' . $event->component . '/' . $event->action . ')', DEBUG_DEVELOPER);
            }

            // Initialize AWS EventBridge handler
            $handler = new aws_eventbridge();
            
            // Send event to AWS EventBridge
            $result = $handler->send_event($event);
            
            if ($debug && $result) {
                debugging('Event successfully processed: ' . $event->eventname, DEBUG_DEVELOPER);
            }
        } catch (\Exception $e) {
            debugging('Error in AWS Events observer: ' . $e->getMessage(), DEBUG_NORMAL);
            if ($debug) {
                debugging('Event that caused error: ' . $event->eventname . ' - ' . json_encode($event), DEBUG_DEVELOPER);
            }
        }
    }
}