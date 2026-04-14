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

            // Filter: Only process file-related modules for course_module events
            if ($event->eventname === '\core\event\course_module_created' || 
                $event->eventname === '\core\event\course_module_deleted') {
                
                $other = $event->other;
                $modulename = isset($other['modulename']) ? $other['modulename'] : null;
                
                // Only process resource and folder modules (file-related activities)
                if (!in_array($modulename, ['resource', 'folder'])) {
                    if ($debug) {
                        debugging('Skipping non-file module: ' . $modulename, DEBUG_DEVELOPER);
                    }
                    return;
                }
                
                if ($debug) {
                    debugging('Processing file module: ' . $modulename, DEBUG_DEVELOPER);
                }
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