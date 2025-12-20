<?php

// Copyright (c) Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

/**
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

defined('MOODLE_INTERNAL') || die;

if (isset($ADMIN) && $ADMIN->fulltree) {
    $settings->add(new admin_setting_configtext(
        'block_aitranslator/api_gateway_url',
        get_string('api_gateway_url', 'block_aitranslator'),
        get_string('api_gateway_url_desc', 'block_aitranslator'),
        '',
        PARAM_URL
    ));
}