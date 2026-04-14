<?php
// Copyright (c) Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

/**
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

defined('MOODLE_INTERNAL') || die();

$plugin->version   = 2026041300;        
$plugin->requires  = 2022112800;        // Requires Moodle 4.4+.
$plugin->component = 'local_awsevents'; 
$plugin->maturity  = MATURITY_BETA;     
$plugin->release   = '0.10.0-beta';      

// Plugin dependencies.
$plugin->dependencies = [
    'local_aws' => ANY_VERSION,         // Requires local_aws plugin (any version).
];