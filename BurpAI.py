from burp import IBurpExtender, IHttpListener, ITab, IBurpExtenderCallbacks, IHttpService
from javax.swing import JPanel, JTextArea, JScrollPane, SwingUtilities
import threading
import traceback
import re
import logging
import sys

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
        self.safe_append_text(u"Extension initialized.\n")
        logging.info("Extension initialized.")

    def getTabCaption(self):
        return "AEye"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        self.safe_append_text(u"processHttpMessage called. ToolFlag: " + str(toolFlag) + ", MessageIsRequest: " + str(messageIsRequest) + u"\n")
        logging.debug("processHttpMessage called. ToolFlag: " + str(toolFlag) + ", MessageIsRequest: " + str(messageIsRequest))
        # Check if the request/response is from the Repeater or Proxy tool
        if toolFlag in [IBurpExtenderCallbacks.TOOL_REPEATER, IBurpExtenderCallbacks.TOOL_PROXY]:
            self.safe_append_text(u"Tool is Repeater or Proxy.\n")
            logging.debug("Tool is Repeater or Proxy.")
            if not messageIsRequest:
                self.safe_append_text(u"Message is a Response. Starting new thread to handle response.\n")
                logging.debug("Message is a Response. Starting new thread to handle response.")
                # Start a new thread to handle the analysis
                threading.Thread(target=self.handle_response, args=(messageInfo,)).start()
            else:
                self.safe_append_text(u"Message is a Request. Ignoring.\n")
                logging.debug("Message is a Request. Ignoring.")
        else:
            self.safe_append_text(u"Tool is not Repeater or Proxy. Ignoring message.\n")
            logging.debug("Tool is not Repeater or Proxy. Ignoring message.")

    def handle_response(self, messageInfo):
        try:
            self.safe_append_text(u"handle_response started...\n")
            logging.debug("handle_response started...")
            response = messageInfo.getResponse()
            request = messageInfo.getRequest()  # Get the request associated with the response
            if response and request:
                self.safe_append_text(u"Response and request received. Analyzing...\n")
                logging.debug("Response and request received. Analyzing...")

                # Get full request as a string
                request_str = self.helpers.bytesToString(request)
                if not isinstance(request_str, unicode):
                    request_str = unicode(request_str, 'utf-8', 'replace')
                self.safe_append_text(u"Original request length: " + str(len(request_str)) + u"\n")
                logging.debug("Original request length: " + str(len(request_str)))

                # Get full response as a string
                response_str = self.helpers.bytesToString(response)
                if not isinstance(response_str, unicode):
                    response_str = unicode(response_str, 'utf-8', 'replace')
                self.safe_append_text(u"Original response length: " + str(len(response_str)) + u"\n")
                logging.debug("Original response length: " + str(len(response_str)))

                self.safe_append_text(u"Received request and response for analysis...\n")
                logging.debug("Received request and response for analysis...")

                # Analyze with OpenAI
                insights = self.analyze_with_openai(request_str, response_str)
                self.update_text_area(insights)
            else:
                self.safe_append_text(u"No response or request to handle.\n")
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
        except Exception as e:
                # Log exception to console and file
                print("Exception in safe_append_text: " + str(e))
                traceback.print_exc()
                logging.error("Exception in safe_append_text: " + str(e))
                logging.error("Traceback:\n" + traceback.format_exc()).
    SwingUtilities.invokeLater(append)

    def update_text_area(self, insights):
        def append_text():
            try:
                self.text_area.append(u"AI Analysis Results:\n")
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
            self.safe_append_text(u"Creating payload...\n")
            logging.debug("Creating payload...")
            data = self.create_payload(request_data, response_data)
            self.safe_append_text(u"Payload created. Length: " + str(len(data)) + u"\n")
            logging.debug("Payload created. Length: " + str(len(data)))
            self.safe_append_text(u"Payload data:\n" + data + u"\n")
            logging.debug("Payload data:\n" + data)
            self.safe_append_text(u"Setting up request to OpenAI API using Burp's API...\n")
            logging.debug("Setting up request to OpenAI API using Burp's API...")

            # Construct the HTTP request to the OpenAI API
            https_service = self.helpers.buildHttpService("api.openai.com", 443, True)
            self.safe_append_text(u"HTTP service created.\n")
            logging.debug("HTTP service created.")

            headers = [
                "POST /v1/chat/completions HTTP/1.1",
                "Host: api.openai.com",
                "Content-Type: application/json",
                "Authorization: Bearer " + self.openai_api_key,
                "Connection: close"
            ]
            self.safe_append_text(u"Request headers set.\n")
            logging.debug("Request headers set.")

            # Use UTF-8 encoding
            if not isinstance(data, str):
                data = data.encode('utf-8')
            self.safe_append_text(u"Request body encoded.\n")
            logging.debug("Request body encoded.")

            request_message = self.helpers.buildHttpMessage(headers, data)
            self.safe_append_text(u"HTTP request message built.\n")
            logging.debug("HTTP request message built.")
            self.safe_append_text(u"Sending request to OpenAI API...\n")
            logging.debug("Sending request to OpenAI API...")

            response = self.callbacks.makeHttpRequest(https_service, request_message)
            self.safe_append_text(u"Received response from OpenAI API.\n")
            logging.debug("Received response from OpenAI API.")

            analyzedResponse = self.helpers.analyzeResponse(response.getResponse())
            http_status = analyzedResponse.getStatusCode()
            self.safe_append_text(u"HTTP Status Code from OpenAI API: " + str(http_status) + u"\n")
            logging.debug("HTTP Status Code from OpenAI API: " + str(http_status))

            response_body = response.getResponse()[analyzedResponse.getBodyOffset():]
            response_body_str = self.helpers.bytesToString(response_body)
            if not isinstance(response_body_str, unicode):
                response_body_str = unicode(response_body_str, 'utf-8', 'replace')
            self.safe_append_text(u"Response body obtained.\n")
            logging.debug("Response body obtained.")
            self.safe_append_text(u"Parsing response...\n")
            logging.debug("Parsing response...")
            return self.parse_openai_response(response_body_str)
        except Exception, e:
            self.log_exception("Exception occurred during OpenAI analysis", e)
            return u"OpenAI Analysis Error"

    def create_payload(self, request_data, response_data):
        try:
            self.safe_append_text(u"In create_payload... constructing payload with pagination.\n")
            logging.debug("In create_payload... constructing payload with pagination.")

            # Split the data into chunks of 1000 characters
            chunk_size = 1000
            request_chunks = [request_data[i:i+chunk_size] for i in range(0, len(request_data), chunk_size)]
            response_chunks = [response_data[i:i+chunk_size] for i in range(0, len(response_data), chunk_size)]

            total_chunks = len(request_chunks) + len(response_chunks)
            self.safe_append_text(u"Total chunks: " + str(total_chunks) + u"\n")
            logging.debug("Total chunks: " + str(total_chunks))

            # Build the payload using lists and dictionaries
            messages = []

            # System message
            system_content = (
                u"You are a security expert analyzing paginated HTTP requests and responses. "
                u"I will send you data in chunks. Wait until you have received all chunks before responding."
            )
            messages.append({"role": "system", "content": system_content})

            # Inform the AI about the total number of chunks
            total_chunks_msg = u"Total chunks to expect: " + str(total_chunks)
            messages.append({"role": "user", "content": total_chunks_msg})

            # Add request chunks
            chunk_index = 1
            for chunk in request_chunks:
                message_content = u"Request Chunk " + str(chunk_index) + u"/" + str(total_chunks) + u":\n" + chunk
                messages.append({"role": "user", "content": message_content})
                chunk_index += 1

            # Add response chunks
            for chunk in response_chunks:
                message_content = u"Response Chunk " + str(chunk_index) + u"/" + str(total_chunks) + u":\n" + chunk
                messages.append({"role": "user", "content": message_content})
                chunk_index += 1

            # Final message to tell the AI to proceed with analysis
            end_message_content = (
                u"End of data. Please analyze the given request and response data and suggest security tests or potential vulnerabilities."
            )
            messages.append({"role": "user", "content": end_message_content})

            # Build the payload dictionary
            payload_dict = {"model": "gpt-3.5-turbo", "messages": messages}

            # Now serialize the payload_dict to a JSON string using custom function
            payload_json = self.dict_to_json(payload_dict)
            self.safe_append_text(u"Payload JSON string with pagination created.\n")
            logging.debug("Payload JSON string with pagination created.")
            self.safe_append_text(u"Payload JSON:\n" + payload_json + u"\n")
            logging.debug("Payload JSON:\n" + payload_json)

            # Check the payload size and limit it if necessary
            payload_size_limit = 15000  # Adjust based on OpenAI's input size limits
            current_size = len(payload_json)
            if current_size > payload_size_limit:
                self.safe_append_text(u"Payload size exceeds limit. Truncating data to fit within limits.\n")
                logging.warning("Payload size exceeds limit. Truncating data to fit within limits.")
                # Truncate the messages to fit within size limits
                while current_size > payload_size_limit and len(messages) > 3:
                    # Remove chunks from the middle to preserve initial instructions and final message
                    messages.pop(2)  # Remove the third message (first data chunk)
                    payload_dict["messages"] = messages
                    payload_json = self.dict_to_json(payload_dict)
                    current_size = len(payload_json)
                self.safe_append_text(u"Adjusted payload size: " + str(current_size) + u"\n")
                logging.debug("Adjusted payload size: " + str(current_size))

            return payload_json
        except Exception, e:
            self.log_exception("Exception occurred in create_payload", e)
            raise  # Re-raise exception to be caught in analyze_with_openai

    def dict_to_json(self, obj):
        try:
            if isinstance(obj, dict):
                items = []
                for key, value in obj.items():
                    key_str = self.json_stringify(key)
                    value_str = self.dict_to_json(value)
                    items.append(u'%s:%s' % (key_str, value_str))
                return u'{' + u','.join(items) + u'}'
            elif isinstance(obj, list):
                items = [self.dict_to_json(element) for element in obj]
                return u'[' + u','.join(items) + u']'
            elif isinstance(obj, unicode):
                return self.json_stringify(obj)
            elif isinstance(obj, str):
                return self.json_stringify(unicode(obj, 'utf-8', 'replace'))
            elif isinstance(obj, bool):
                return u'true' if obj else u'false'
            elif isinstance(obj, int) or isinstance(obj, float):
                return unicode(obj)
            elif obj is None:
                return u'null'
            else:
                # Convert other types to strings
                return self.json_stringify(unicode(str(obj), 'utf-8', 'replace'))
        except Exception, e:
            self.log_exception("Exception in dict_to_json", e)
            raise

    def json_stringify(self, s):
        try:
            if not isinstance(s, unicode):
                s = unicode(s, 'utf-8', 'replace')
            # Use JSON-compliant escaping
            escape_map = {
                u'\\': u'\\\\',
                u'"': u'\\"',
                u'\b': u'\\b',
                u'\f': u'\\f',
                u'\n': u'\\n',
                u'\r': u'\\r',
                u'\t': u'\\t',
            }
            s = u''.join(escape_map.get(c, c) if ord(c) >= 0x20 else u'\\u%04x' % ord(c) for c in s)
            return u'"' + s + u'"'
        except Exception, e:
            self.log_exception("Exception in json_stringify", e)
            raise

    def parse_openai_response(self, response):
        try:
            self.safe_append_text(u"Parsing OpenAI response manually...\n")
            logging.debug("Parsing OpenAI response manually...")
            if not isinstance(response, unicode):
                response_decoded = unicode(response, 'utf-8', 'replace')
            else:
                response_decoded = response
            self.safe_append_text(u"OpenAI raw response:\n" + response_decoded + u"\n")
            logging.debug("OpenAI raw response:\n" + response_decoded)

            # Find the start of the "choices" array
            choices_start = response_decoded.find(u'"choices"')
            if choices_start == -1:
                self.safe_append_text(u"'choices' not found in OpenAI response.\n")
                logging.error("'choices' not found in OpenAI response.")
                return u"Failed to parse OpenAI response"
            
            # Find the '[' after "choices"
            choices_array_start = response_decoded.find(u'[', choices_start)
            if choices_array_start == -1:
                self.safe_append_text(u"Start of choices array not found.\n")
                logging.error("Start of choices array not found.")
                return u"Failed to parse OpenAI response"
            
            # Find the matching ']' for the choices array
            choices_array_end = self.find_matching_bracket(response_decoded, choices_array_start)
            if choices_array_end == -1:
                self.safe_append_text(u"End of choices array not found.\n")
                logging.error("End of choices array not found.")
                return u"Failed to parse OpenAI response"
            
            choices_str = response_decoded[choices_array_start:choices_array_end+1]
            
            # Find the "content" field within the choices array
            content_pattern = r'"content"\s*:\s*"((?:\\.|[^"\\])*)"'
            content_match = re.search(content_pattern, choices_str, re.DOTALL)
            if content_match:
                content = content_match.group(1)
                # Unescape escaped characters
                content_decoded = content.replace(u'\\n', u'\n').replace(u'\\"', u'"').replace(u'\\\\', u'\\')
                self.safe_append_text(u"Parsed content from OpenAI response.\n")
                logging.debug("Parsed content from OpenAI response.")
                return content_decoded.strip()
            else:
                self.safe_append_text(u"Failed to parse 'content' from OpenAI response.\n")
                self.safe_append_text(u"Full choices string:\n" + choices_str + u"\n")
                logging.error("Failed to parse 'content' from OpenAI response.")
                logging.error("Full choices string:\n" + choices_str)
                return u"Failed to parse OpenAI response"
            
        except Exception, e:
            self.log_exception("Exception occurred during parsing", e)
            return u"Failed to parse OpenAI response"

    def find_matching_bracket(self, s, start_pos):
        bracket_stack = []
        for i in range(start_pos, len(s)):
            if s[i] == u'[':
                bracket_stack.append('[')
            elif s[i] == u']':
                bracket_stack.pop()
                if not bracket_stack:
                    return i
        return -1  # No matching closing bracket found
    
    def log_uncaught_exceptions(self, exctype, value, tb):
        logging.error("Uncaught exception:", exc_info=(exctype, value, tb))