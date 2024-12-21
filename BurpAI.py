from burp import IBurpExtender, IHttpListener, ITab, IBurpExtenderCallbacks, IHttpService
from javax.swing import JPanel, JTextArea, JScrollPane, SwingUtilities
import threading
import traceback
import re
import logging
import sys

# Import simplejson without using 'as' keyword
import simplejson

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        # Set up logging
        logging.basicConfig(
            filename='burp_extension.log',
            level=logging.DEBUG,
            format='%(asctime)s %(levelname)s:%(message)s'
        )
        # Log uncaught exceptions
        sys.excepthook = self.log_uncaught_exceptions
        self.callbacks = callbacks  # Save the callbacks for later use
        self.helpers = callbacks.getHelpers()  # Get the helpers from callbacks
        callbacks.setExtensionName("AI Insights and Payload Suggestion")
        callbacks.registerHttpListener(self)
        self.openai_api_key = ''  # Replace with your actual OpenAI API key
        # Initialize UI components
        self.panel = JPanel()
        self.text_area = JTextArea(20, 60)  # Text area to display results
        self.text_area.setEditable(False)
        scroll_pane = JScrollPane(self.text_area)
        self.panel.add(scroll_pane)
        # Add the tab to Burp Suite
        callbacks.addSuiteTab(self)
        logging.info("Extension initialized.")

    def getTabCaption(self):
        return "AEye"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        logging.debug("processHttpMessage called. ToolFlag: " + str(toolFlag) + ", MessageIsRequest: " + str(messageIsRequest))
        # Check if the request/response is from the Repeater or Proxy tool
        if toolFlag in [IBurpExtenderCallbacks.TOOL_REPEATER, IBurpExtenderCallbacks.TOOL_PROXY]:
            logging.debug("Tool is Repeater or Proxy.")
            if not messageIsRequest:
                logging.debug("Message is a Response. Starting new thread to handle response.")
                # Start a new thread to handle the analysis
                threading.Thread(target=self.handle_response, args=(messageInfo,)).start()
            else:
                logging.debug("Message is a Request. Ignoring.")
        else:
            logging.debug("Tool is not Repeater or Proxy. Ignoring message.")

    def handle_response(self, messageInfo):
        try:
            logging.debug("handle_response started...")
            response = messageInfo.getResponse()
            request = messageInfo.getRequest()  # Get the request associated with the response
            if response and request:
                logging.debug("Response and request received. Analyzing...")
                # Get full request as a string
                request_str = self.helpers.bytesToString(request)
                if not isinstance(request_str, unicode):
                    request_str = unicode(request_str, 'utf-8', 'replace')
                logging.debug("Original request length: " + str(len(request_str)))
                # Get full response as a string
                response_str = self.helpers.bytesToString(response)
                if not isinstance(response_str, unicode):
                    response_str = unicode(response_str, 'utf-8', 'replace')
                logging.debug("Original response length: " + str(len(response_str)))
                logging.debug("Received request and response for analysis...")
                # Analyze with OpenAI
                insights = self.analyze_with_openai(request_str, response_str)
                self.update_text_area(insights)
            else:
                logging.warning("No response or request to handle.")
        except Exception, e:
            self.log_exception("Exception occurred in handle_response", e)

    def safe_append_text(self, text):
        def append():
            try:
                local_text = text
                if not isinstance(local_text, unicode):
                    local_text = unicode(local_text, 'utf-8', 'replace')
                self.text_area.append(local_text)
            except Exception, e:
                # Log exception to console and file
                print("Exception in safe_append_text: " + str(e))
                traceback.print_exc()
                logging.error("Exception in safe_append_text: " + str(e))
                logging.error("Traceback:\n" + traceback.format_exc())
        SwingUtilities.invokeLater(append)

    def update_text_area(self, insights):
        def append_text():
            try:
                self.text_area.append(u"AEye Analysis Results:\n \n")
                self.text_area.append(insights + u"\n\n")
            except Exception, e:
                # Log exception to console and file
                print("Exception in update_text_area: " + str(e))
                traceback.print_exc()
                logging.error("Exception in update_text_area: " + str(e))
                logging.error("Traceback:\n" + traceback.format_exc())
        SwingUtilities.invokeLater(append_text)

    def analyze_with_openai(self, request_data, response_data):
        try:
            logging.debug("Creating payload...")
            data = self.create_payload(request_data, response_data[:100000])
            logging.debug("Payload created. Length: " + str(len(data)))
            logging.debug("Payload data:\n" + data)
            logging.debug("Setting up request to OpenAI API using Burp's API...")
            # Construct the HTTP request to the OpenAI API
            https_service = self.helpers.buildHttpService("api.openai.com", 443, True)
            logging.debug("HTTP service created.")
            headers = [
                "POST /v1/chat/completions HTTP/1.1",
                "Host: api.openai.com",
                "Content-Type: application/json",
                "Authorization: Bearer " + self.openai_api_key,
                "Connection: close"
            ]
            logging.debug("Request headers set.")
            # Use UTF-8 encoding
            if not isinstance(data, str):
                data = data.encode('utf-8')
            logging.debug("Request body encoded.")
            request_message = self.helpers.buildHttpMessage(headers, data)
            logging.debug("HTTP request message built.")
            logging.debug("Sending request to OpenAI API...")
            response = self.callbacks.makeHttpRequest(https_service, request_message)
            logging.debug("Received response from OpenAI API.")
            analyzedResponse = self.helpers.analyzeResponse(response.getResponse())
            http_status = analyzedResponse.getStatusCode()
            logging.debug("HTTP Status Code from OpenAI API: " + str(http_status))
            response_body = response.getResponse()[analyzedResponse.getBodyOffset():]
            response_body_str = self.helpers.bytesToString(response_body)
            if not isinstance(response_body_str, unicode):
                response_body_str = unicode(response_body_str, 'utf-8', 'replace')
            logging.debug("Response body obtained.")
            logging.debug("Parsing response...")
            return self.parse_openai_response(response_body_str)
        except Exception, e:
            self.log_exception("Exception occurred during OpenAI analysis", e)
            return u"OpenAI Analysis Error"

    def create_payload(self, request_data, response_data):
        try:
            logging.debug("In create_payload... constructing payload.")
            # Combine the request and response data
            input_data = request_data + "\n\n" + response_data
            # Build the payload dictionary
            messages = [
                {
                    "role": "system",
                    "content": (
                        u"You are a security expert analyzing HTTP requests and responses, helping me do white hat bug bounty. "
                        u"Please analyze the request attempt and the server response, to check for any exploitability oppourtunity and/or vulnerabilities."
                        u"Please analyze the given data and suggest further research and/or payloads to test for vulnerabilities."
                    )
                },
                {
                    "role": "user",
                    "content": input_data
                }
            ]
            payload_dict = {
                "model": "gpt-4o-mini",
                "messages": messages
            }
            # Serialize the payload_dict to a JSON string using simplejson
            payload_json = simplejson.dumps(payload_dict, ensure_ascii=False)
            logging.debug("Payload JSON string created.")
            logging.debug("Payload JSON:\n" + payload_json)
            # Check the payload size and truncate if necessary
            payload_size_limit = 15000  # Adjust based on OpenAI's input size limits
            current_size = len(payload_json)
            if current_size > payload_size_limit:
                logging.warning("Payload size exceeds limit. Truncating data to fit within limits.")
                # Truncate the input_data to fit within the payload size limit
                # Adjust by subtracting estimated overhead
                overhead = current_size - len(input_data)
                max_input_size = payload_size_limit - overhead
                input_data = input_data[:max_input_size]
                messages[1]["content"] = input_data
                payload_dict["messages"] = messages
                payload_json = simplejson.dumps(payload_dict, ensure_ascii=False)
                logging.debug("Adjusted payload size: " + str(len(payload_json)))
            return payload_json
        except Exception, e:
            raise  # Re-raise exception to be caught in analyze_with_openai

    def parse_openai_response(self, response):
        try:
            logging.debug("Parsing OpenAI response with simplejson...")
            if not isinstance(response, unicode):
                response = unicode(response, 'utf-8', 'replace')
            # Parse the JSON response using simplejson
            response_json = simplejson.loads(response)
            # Extract the content from the JSON structure
            choices = response_json.get('choices', [])
            if not choices:
                logging.error("'choices' not found or empty in OpenAI response: /n" + response)
                return u"Failed to parse OpenAI response"
            first_choice = choices[0]
            message = first_choice.get('message', {})
            content = message.get('content', '')
            logging.debug("Parsed content from OpenAI response.")
            return content.strip()
        except Exception, e:
            self.log_exception("Exception occurred during parsing", e)
            return u"Failed to parse OpenAI response"

    def log_exception(self, message, e):
        error_message = message + ": " + str(e)
        logging.error(error_message)
        logging.error("Traceback:\n" + traceback.format_exc())

    def log_uncaught_exceptions(self, exctype, value, tb):
        logging.error("Uncaught exception:", exc_info=(exctype, value, tb))