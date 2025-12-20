<?php

// Copyright (c) Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

/**
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

require_once($CFG->libdir . '/externallib.php');

class block_aitranslator extends block_base
{
    public function init()
    {
        $this->title = get_string('pluginname', 'block_aitranslator');
    }

    public function has_config()
    {
        return true;
    }

    public function get_content()
    {
        if ($this->content !== null) {
            return $this->content;
        }

        $this->content = new stdClass();

        $sesskey = sesskey();
        if (empty($sesskey)) {
            $this->content->text = '<p>Error: Unable to initialize security token.</p>';
            return $this->content;
        }
        $sesskey_escaped = json_encode($sesskey, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        
        $this->content->text = '
            <input type="text" id="aitranslator_question" placeholder="Ask AI..." style="width: 100%;">
            <br><br>
            <button id="aitranslator_button">Ask AI</button>
            <div id="aitranslator_response" style="margin-top: 10px;"></div>

            <script>
                const sesskey = ' . $sesskey_escaped . ';
                document.getElementById("aitranslator_button").addEventListener("click", async function(event) {
                    const questionInput = document.getElementById("aitranslator_question");
                    const responseDiv = document.getElementById("aitranslator_response");
                    const prompt = questionInput.value.trim();

                    if (!prompt) {
                        responseDiv.innerHTML = "<em>Please enter a question.</em>";
                        return;
                    }

                    responseDiv.innerHTML = "<em>Thinking...</em>";

                    try {
                        const response = await fetch("", {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/x-www-form-urlencoded"
                            },
                            body: "aitranslator_ajax=1&sesskey=" + encodeURIComponent(sesskey) + "&aitranslator_question=" + encodeURIComponent(prompt)
                        });

                        if (!response.ok) {
                            responseDiv.innerHTML = "<span style=\'color: red;\'>Server error. Please try again.</span>";
                            return;
                        }

                        const text = await response.text();
                        const sanitizedText = document.createTextNode(text);
                        const answerLabel = document.createElement("strong");
                        answerLabel.textContent = "Answer: ";
                        responseDiv.innerHTML = "";
                        responseDiv.appendChild(answerLabel);
                        responseDiv.appendChild(sanitizedText);
                    } catch (err) {
                        responseDiv.innerHTML = "<span style=\'color: red;\'>Error contacting AI.</span>";
                    }
                });
            </script>
        ';

        // Handle AJAX request
        if (!empty($_POST['aitranslator_ajax']) && !empty($_POST['aitranslator_question'])) {
            require_login();
            require_sesskey();
            
            $question = required_param('aitranslator_question', PARAM_TEXT);
            
            try {
                $response = $this->get_ai_response($question);
                if (strpos($response, 'Error:') === 0) {
                    http_response_code(500);
                    echo htmlentities('Unable to process request', ENT_QUOTES, 'UTF-8');
                } else {
                    echo htmlentities($response, ENT_QUOTES, 'UTF-8');
                }
            } catch (Exception $e) {
                http_response_code(500);
                debugging('AI Translator error: ' . $e->getMessage(), DEBUG_DEVELOPER);
                echo htmlentities('An error occurred', ENT_QUOTES, 'UTF-8');
            }
            exit;
        }

        return $this->content;
    }

    private function get_user_token() {
        global $DB;       
        
        $service = $DB->get_record('external_services', ['shortname' => 'ai_translator']);
        
        if (!$service) {
            debugging('AI Translator service not found. Please configure the ai_translator external service.', DEBUG_DEVELOPER);
            return false;
        }
        
        try {
            $tokenobj = external_generate_token_for_current_user($service);
            
            if (!$tokenobj || empty($tokenobj->token)) {
                debugging('Failed to generate token for current user', DEBUG_DEVELOPER);
                return false;
            }
            
            return $tokenobj->token;
        } catch (Exception $e) {
            debugging('Error generating user token: ' . $e->getMessage(), DEBUG_DEVELOPER);
            return false;
        }
    }
    private function get_ai_response(string $prompt): string
    {
        $apiUrl = get_config('block_aitranslator', 'api_gateway_url');
        if (empty($apiUrl)) {
            return 'Error: API Gateway URL not configured';
        }

        $token = $this->get_user_token();
        if (!$token) {
            return 'Error: Unable to get user token';
        }

        $data = json_encode(['prompt' => $prompt]);

        $ch = curl_init($apiUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $token
        ]);


        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_errno($ch);
        $curlErrorMsg = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            debugging('cURL error: ' . $curlErrorMsg, DEBUG_DEVELOPER);
            return 'Error: Network error occurred';
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            debugging('HTTP error: ' . $httpCode, DEBUG_DEVELOPER);
            return 'Error: Server returned error code ' . $httpCode;
        }

        if (empty($response)) {
            return 'Error: Empty response from server';
        }

        $result = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            debugging('JSON decode error: ' . json_last_error_msg(), DEBUG_DEVELOPER);
            return 'Error: Invalid response format';
        }

        if (!is_array($result) || !isset($result['output'])) {
            debugging('Missing output in response', DEBUG_DEVELOPER);
            return 'Error: Invalid response structure';
        }

        return $result['output'];
    }
}

