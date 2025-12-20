<?php
// Copyright (c) Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

/**
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

defined('MOODLE_INTERNAL') || die();

if ($hassiteconfig) {
    // Create settings page
    $settings = new admin_settingpage('local_awsevents', get_string('pluginname', 'local_awsevents'));
    $ADMIN->add('localplugins', $settings);

    // Enable/disable debug logging
    $settings->add(new admin_setting_configcheckbox(
        'local_awsevents_debug',
        get_string('debug', 'local_awsevents'),
        get_string('debug_desc', 'local_awsevents'),
        0
    ));

    // Authentication Method
    $settings->add(new admin_setting_configselect(
        'local_awsevents_auth_method',
        get_string('awsauthmethod', 'local_awsevents'),
        get_string('awsauthmethod_desc', 'local_awsevents'),
        'role',
        array(
            'key' => get_string('awsauthmethod_key', 'local_awsevents'),
            'role' => get_string('awsauthmethod_role', 'local_awsevents')
        )
    ));

    // AWS Region
    $settings->add(new admin_setting_configtext(
        'local_awsevents_region',
        get_string('awsregion', 'local_awsevents'),
        get_string('awsregion_desc', 'local_awsevents'),
        'us-west-2'
    ));

    // AWS Access Key
    $settings->add(new admin_setting_configtext(
        'local_awsevents_key',
        get_string('awskey', 'local_awsevents'),
        get_string('awskey_desc', 'local_awsevents'),
        ''
    ));

    // AWS Secret Key
    $settings->add(new admin_setting_configpasswordunmask(
        'local_awsevents_secret',
        get_string('awssecret', 'local_awsevents'),
        get_string('awssecret_desc', 'local_awsevents'),
        ''
    ));

    // EventBridge Event Bus Name
    $settings->add(new admin_setting_configtext(
        'local_awsevents_eventbus',
        get_string('eventbus', 'local_awsevents'),
        get_string('eventbus_desc', 'local_awsevents'),
        'moodle-events'
    ));
}