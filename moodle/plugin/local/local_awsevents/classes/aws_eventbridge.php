<?php
// Copyright (c) Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

/**
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

/**
 * AWS EventBridge integration class
 *
 * @package    local_awsevents
 * @copyright  2024 Your Name <your@email.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace local_awsevents;

use Aws\EventBridge\EventBridgeClient;
use core\event\base;

defined('MOODLE_INTERNAL') || die();

/**
 * Class aws_eventbridge
 *
 * Handles the integration with AWS EventBridge for sending Moodle events
 */
class aws_eventbridge {
    /** @var EventBridgeClient Cached AWS EventBridge client instance */
    private static $client = null;
    
    /** @var string EventBridge event bus name */
    private $eventbus;

    /**
     * Constructor.
     *
     * @throws \Exception If AWS credentials are not configured
     */
    public function __construct() {
        global $CFG;
        
        // Check if AWS settings are configured
        if (empty($CFG->local_awsevents_region) || empty($CFG->local_awsevents_eventbus)) {
            throw new \Exception('AWS region or EventBridge settings not configured');
        }

        // Initialize client only once (cached across multiple events)
        if (self::$client === null) {
            // Get authentication method
            $auth_method = !empty($CFG->local_awsevents_auth_method) ? $CFG->local_awsevents_auth_method : 'role';

            // Prepare client configuration
            $config = [
                'version' => 'latest',
                'region'  => $CFG->local_awsevents_region
            ];

            // Add credentials based on authentication method
            if ($auth_method === 'key') {
                if (empty($CFG->local_awsevents_key) || empty($CFG->local_awsevents_secret)) {
                    throw new \Exception('AWS access key and secret key are required when using key authentication');
                }
                $config['credentials'] = [
                    'key'    => $CFG->local_awsevents_key,
                    'secret' => $CFG->local_awsevents_secret,
                ];
            }
            // For role authentication, we don't need to specify credentials
            // AWS SDK will automatically use the EC2 instance role

            // Initialize AWS EventBridge client (cached)
            self::$client = new EventBridgeClient($config);
            
            // Debug log the event bus name
            if (!empty($CFG->local_awsevents_debug)) {
                debugging('AWS EventBridge client initialized (cached)', DEBUG_DEVELOPER);
            }
        }
        
        $this->eventbus = $CFG->local_awsevents_eventbus;
    }

    /**
     * Send event to AWS EventBridge
     *
     * @param base $event The Moodle event object
     * @return bool True if successful, false otherwise
     */
    public function send_event(base $event): bool {
        global $CFG;
        $debug = !empty($CFG->local_awsevents_debug);
        
        try {
            // Prepare event detail with error checking
            $detail = json_encode([
                'eventname' => $event->eventname,
                'component' => $event->component,
                'action' => $event->action,
                'target' => $event->target,
                'objecttable' => $event->objecttable,
                'objectid' => $event->objectid,
                'crud' => $event->crud,
                'edulevel' => $event->edulevel,
                'contextid' => $event->contextid,
                'contextlevel' => $event->contextlevel,
                'contextinstanceid' => $event->contextinstanceid,
                'userid' => $event->userid,
                'courseid' => $event->courseid,
                'relateduserid' => $event->relateduserid,
                'anonymous' => $event->anonymous,
                'other' => $event->other,
                'timecreated' => $event->timecreated
            ]);
            
            if ($detail === false) {
                debugging('Failed to encode event data to JSON: ' . json_last_error_msg(), DEBUG_NORMAL);
                return false;
            }
            
            // Prepare event data
            $eventData = [
                'Entries' => [
                    [
                        'EventBusName' => $this->eventbus,
                        'Source' => 'moodle.events',
                        'DetailType' => $event->eventname,
                        'Detail' => $detail,
                        'Time' => new \DateTime()
                    ]
                ]
            ];

            if ($debug) {
                debugging('Sending event to EventBridge: ' . $event->eventname . 
                          ' to bus: ' . $this->eventbus . 
                          ' with detail: ' . $detail, DEBUG_DEVELOPER);
            }

            // Send event to EventBridge (using cached client)
            $result = self::$client->putEvents($eventData);
            
            // Check if event was sent successfully
            if (isset($result['FailedEntryCount']) && $result['FailedEntryCount'] > 0) {
                debugging('Failed to send event to AWS EventBridge: ' . print_r($result, true), DEBUG_NORMAL);
                return false;
            }
            
            if ($debug) {
                debugging('Successfully sent event to EventBridge: ' . 
                          $event->eventname . ' - Response: ' . json_encode($result), DEBUG_DEVELOPER);
            }
            
            return true;
        } catch (\Aws\EventBridge\Exception\EventBridgeException $e) {
            debugging('AWS EventBridge error: ' . $e->getAwsErrorCode() . ' - ' . $e->getMessage(), DEBUG_NORMAL);
            return false;
        } catch (\Aws\Exception\AwsException $e) {
            debugging('AWS SDK error: ' . $e->getAwsErrorCode() . ' - ' . $e->getMessage(), DEBUG_NORMAL);
            return false;
        } catch (\Exception $e) {
            debugging('Unexpected error sending event to AWS EventBridge: ' . $e->getMessage(), DEBUG_NORMAL);
            return false;
        }
    }
}