from burp import IBurpExtender, IHttpListener, ITab, IBurpExtenderCallbacks, IHttpService
from javax.swing import JPanel, JTextArea, JScrollPane, SwingUtilities
import threading
import traceback
import re

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
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
        self.safe_append_text("Extension initialized.\n")

    def getTabCaption(self):
        return "AEye"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        self.safe_append_text("processHttpMessage called. ToolFlag: " + str(toolFlag) + ", MessageIsRequest: " + str(messageIsRequest) + "\n")
        # Check if the request/response is from the Repeater or Proxy tool
        if toolFlag in [IBurpExtenderCallbacks.TOOL_REPEATER, IBurpExtenderCallbacks.TOOL_PROXY]:
            self.safe_append_text("Tool is Repeater or Proxy.\n")
            if not messageIsRequest:
                self.safe_append_text("Message is a Response. Starting new thread to handle response.\n")
                # Start a new thread to handle the analysis
                threading.Thread(target=self.handle_response, args=(messageInfo,)).start()
            else:
                self.safe_append_text("Message is a Request. Ignoring.\n")
        else:
            self.safe_append_text("Tool is not Repeater or Proxy. Ignoring message.\n")

    def handle_response(self, messageInfo):
        self.safe_append_text("handle_response started...\n")
        response = messageInfo.getResponse()
        request = messageInfo.getRequest()  # Get the request associated with the response
        if response and request:
            self.safe_append_text("Response and request received. Analyzing...\n")
            # Get full request as a string
            request_str = self.helpers.bytesToString(request)
            self.safe_append_text("Original request length: " + str(len(request_str)) + "\n")
            if len(request_str) > 500:
                request_str = request_str[:500] + '\n...[truncated]'
                self.safe_append_text("Request truncated to 2000 characters for analysis.\n")

            # Get full response as a string
            response_str = self.helpers.bytesToString(response)
            self.safe_append_text("Original response length: " + str(len(response_str)) + "\n")
            if len(response_str) > 500:
                response_str = response_str[:500] + '\n...[truncated]'
                self.safe_append_text("Response truncated to 2000 characters for analysis.\n")

            self.safe_append_text("Received request and response for analysis...\n")
            try:
                insights = self.analyze_with_openai(request_str, response_str)
            except Exception, e:
                self.safe_append_text("Error while analyzing with OpenAI: " + str(e) + "\n")
                traceback_str = traceback.format_exc()
                self.safe_append_text("Traceback:\n" + traceback_str + "\n")
                insights = "Analysis failed due to an error."
            self.update_text_area(insights)
        else:
            self.safe_append_text("No response or request to handle.\n")

    def safe_append_text(self, text):
        def append():
            try:
                if not isinstance(text, unicode):
                    text = unicode(text)
                self.text_area.append(text)
            except Exception, e:
                print("Error updating text area: " + str(e))
                traceback.print_exc()
        SwingUtilities.invokeLater(append)

    def update_text_area(self, insights):
        def append_text():
            try:
                self.text_area.append("AI Analysis Results:\n")
                self.text_area.append(insights + "\n\n")
            except Exception, e:
                print("Error updating text area: " + str(e))
                traceback.print_exc()
        SwingUtilities.invokeLater(append_text)

    def analyze_with_openai(self, request_data, response_data):
        try:
            self.safe_append_text("Creating payload...\n")
            data = self.create_payload(request_data, response_data)
            self.safe_append_text("Payload created. Length: " + str(len(data)) + "\n")
            self.safe_append_text("Payload data: " + data + "\n")

            self.safe_append_text("Setting up request to OpenAI API using Burp's API...\n")

            # Construct the HTTP request to the OpenAI API
            https_service = self.helpers.buildHttpService("api.openai.com", 443, True)
            self.safe_append_text("HTTP service created.\n")

            headers = [
                "POST /v1/chat/completions HTTP/1.1",
                "Host: api.openai.com",
                "Content-Type: application/json",
                "Authorization: Bearer " + self.openai_api_key,
                "Connection: close"
            ]
            self.safe_append_text("Request headers set.\n")

            # Use UTF-8 encoding
            if not isinstance(data, str):
                data = data.encode('utf-8')
            self.safe_append_text("Request body encoded.\n")

            request_message = self.helpers.buildHttpMessage(headers, data)
            self.safe_append_text("HTTP request message built.\n")

            self.safe_append_text("Sending request to OpenAI API...\n")
            response = self.callbacks.makeHttpRequest(https_service, request_message)
            self.safe_append_text("Received response from OpenAI API.\n")

            analyzedResponse = self.helpers.analyzeResponse(response.getResponse())
            response_body = response.getResponse()[analyzedResponse.getBodyOffset():]
            response_body_str = self.helpers.bytesToString(response_body)
            self.safe_append_text("Response body obtained.\n")

            self.safe_append_text("Parsing response...\n")
            return self.parse_openai_response(response_body_str)

        except Exception, e:
            traceback_str = traceback.format_exc()
            self.safe_append_text("Error during OpenAI analysis: " + unicode(e) + "\nTraceback:\n" + unicode(traceback_str) + "\n")
            return "OpenAI Analysis Error"

    def create_payload(self, request_data, response_data):
        try:
            self.safe_append_text("In create_payload... constructing payload manually.\n")
            # Construct the payload as a JSON string manually
            # Since we cannot use the json module, we'll build the JSON string ourselves
            escaped_request_data = self.escape_string(request_data)
            escaped_response_data = self.escape_string(response_data)
            self.safe_append_text("Escaped Request Data: " + escaped_request_data + "\n")
            self.safe_append_text("Escaped Response Data: " + escaped_response_data + "\n")

            # Build the payload using Unicode strings
            payload_json = u''
            payload_json += u'{'
            payload_json += u'"model":"gpt-3.5-turbo",'
            payload_json += u'"messages":['
            payload_json += u'{'
            payload_json += u'"role":"system",'
            payload_json += u'"content":"You are a security expert analyzing HTTP requests and responses."'
            payload_json += u'},'
            payload_json += u'{'
            payload_json += u'"role":"user",'
            payload_json += u'"content":"Analyze the following HTTP request and response, and suggest security tests or potential vulnerabilities.\\n'
            payload_json += u'\\nRequest:\\n' + escaped_request_data + u'\\n'
            payload_json += u'\\nResponse:\\n' + escaped_response_data + u'"'
            payload_json += u'}'
            payload_json += u']'
            payload_json += u'}'

            self.safe_append_text("Payload JSON string created.\n")
            return payload_json
        except Exception, e:
            traceback_str = traceback.format_exc()
            self.safe_append_text("Exception in create_payload: " + str(e) + "\nTraceback:\n" + traceback_str + "\n")
            raise e  # Re-raise exception to be caught in analyze_with_openai

    def escape_string(self, s):
        try:
            if not isinstance(s, unicode):
                s = unicode(s, 'utf-8', 'replace')  # Convert non-strings or byte strings to Unicode strings
            # Escape backslashes, double quotes, and control characters
            s = s.replace(u'\\', u'\\\\')
            s = s.replace(u'"', u'\\"')
            s = s.replace(u'\n', u'\\n')
            s = s.replace(u'\r', u'\\r')
            s = s.replace(u'\t', u'\\t')
            return s
        except Exception, e:
            self.safe_append_text("Exception in escape_string: " + unicode(e) + "\n")
            traceback_str = traceback.format_exc()
            self.safe_append_text("Traceback:\n" + unicode(traceback_str) + "\n")
            raise e

    def parse_openai_response(self, response):
        try:
            self.safe_append_text("Parsing OpenAI response manually...\n")
            if not isinstance(response, unicode):
                response = response.decode('utf-8')
            self.safe_append_text("OpenAI raw response: " + response + "\n")

            # Check if the response contains an error message
            if '"error"' in response:
                self.safe_append_text("OpenAI API returned an error.\n")
                # Extract the error message
                error_pattern = r'"message"\s*:\s*"((?:\\.|[^"\\])*)"'
                error_match = re.search(error_pattern, response, re.DOTALL)
                if error_match:
                    error_message = error_match.group(1)
                    # Unescape any escaped characters
                    error_message = error_message.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
                    self.safe_append_text("Error message from OpenAI: " + error_message + "\n")
                    return "OpenAI API Error: " + error_message
                else:
                    self.safe_append_text("Failed to parse error message from OpenAI response.\n")
                    return "Failed to parse OpenAI response"

            # Proceed with normal parsing if no error is found
            # Updated pattern to match the content field more reliably
            content_pattern = r'"content"\s*:\s*"((?:\\.|[^"\\])*)"'
            match = re.search(content_pattern, response, re.DOTALL)
            if match:
                content = match.group(1)
                # Unescape escaped characters
                content = content.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
                self.safe_append_text("Parsed content from OpenAI response.\n")
                return content.strip()
            else:
                self.safe_append_text("Failed to parse 'content' from OpenAI response.\n")
                # Log the entire response for debugging
                self.safe_append_text("Entire OpenAI response:\n" + response + "\n")
                return "Failed to parse OpenAI response"

        except Exception, e:
            self.safe_append_text("Failed to parse OpenAI response: " + unicode(e) + "\n")
            traceback_str = traceback.format_exc()
            self.safe_append_text("Traceback:\n" + unicode(traceback_str) + "\n")
            return "Failed to parse OpenAI response"