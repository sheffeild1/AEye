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
        if response:
            self.safe_append_text("Response received. Analyzing response...\n")
            analyzedResponse = self.helpers.analyzeResponse(response)
            bodyOffset = analyzedResponse.getBodyOffset()
            responseBytes = response
            responseBodyBytes = responseBytes[bodyOffset:]
            responseBody = self.helpers.bytesToString(responseBodyBytes)
            self.safe_append_text("Response body length: " + str(len(responseBody)) + "\n")
            if len(responseBody) > 100000:
                responseBody = responseBody[:100000] + '\n...[truncated]'
                self.safe_append_text("Response body truncated to 1000 characters for analysis.\n")
            self.safe_append_text("Received response body for analysis...\n")
            try:
                insights = self.analyze_with_openai(responseBody)
            except Exception, e:
                self.safe_append_text("Error while analyzing with OpenAI: " + str(e) + "\n")
                traceback_str = traceback.format_exc()
                self.safe_append_text("Traceback:\n" + traceback_str + "\n")
                insights = "Analysis failed due to an error."
            self.update_text_area(insights)
        else:
            self.safe_append_text("No response to handle.\n")

    def safe_append_text(self, text):
        def append():
            try:
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

    def analyze_with_openai(self, response_data):
        try:
            self.safe_append_text("Creating payload...\n")
            data = self.create_payload(response_data)
            self.safe_append_text("Payload created. Length: " + str(len(data)) + "\n")
            self.safe_append_text("Payload data: " + data + "\n")

            self.safe_append_text("Setting up request to OpenAI API using Burp's API...\n")

            # Construct the HTTP request to the OpenAI API
            # Define the HTTP service (host, port, protocol)
            https_service = self.helpers.buildHttpService("api.openai.com", 443, True)
            self.safe_append_text("HTTP service created.\n")

            # Construct the HTTP request headers
            headers = [
                "POST /v1/chat/completions HTTP/1.1",
                "Host: api.openai.com",
                "Content-Type: application/json",
                "Authorization: Bearer " + self.openai_api_key,
                "Connection: close"
            ]
            self.safe_append_text("Request headers set.\n")

            # Convert the data to bytes
            request_body = data.encode('utf-8')
            self.safe_append_text("Request body encoded.\n")

            # Build the HTTP request
            request_message = self.helpers.buildHttpMessage(headers, request_body)
            self.safe_append_text("HTTP request message built.\n")

            # Send the HTTP request using Burp's callbacks
            self.safe_append_text("Sending request to OpenAI API...\n")
            response = self.callbacks.makeHttpRequest(https_service, request_message)
            self.safe_append_text("Received response from OpenAI API.\n")

            # Analyze the response
            analyzedResponse = self.helpers.analyzeResponse(response.getResponse())
            response_body = response.getResponse()[analyzedResponse.getBodyOffset():]
            response_body_str = self.helpers.bytesToString(response_body)
            self.safe_append_text("Response body obtained.\n")

            self.safe_append_text("Parsing response...\n")
            return self.parse_openai_response(response_body_str)

        except Exception, e:
            traceback_str = traceback.format_exc()
            self.safe_append_text("Error during OpenAI analysis: " + str(e) + "\nTraceback:\n" + traceback_str + "\n")
            return "OpenAI Analysis Error"

    def create_payload(self, response_data):
        try:
            self.safe_append_text("In create_payload... constructing payload manually.\n")
            # Construct the payload as a JSON string manually
            # Since we cannot use the json module, we'll build the JSON string ourselves
            escaped_response_data = self.escape_string(response_data)
            self.safe_append_text("Escaped Response Data: " + escaped_response_data + "\n")

            payload_json = ''
            payload_json += '{'
            payload_json += '"model":"gpt-3.5-turbo",'
            payload_json += '"messages":['
            payload_json += '{'
            payload_json += '"role":"system",'
            payload_json += '"content":"You are a security expert analyzing web responses."'
            payload_json += '},'
            payload_json += '{'
            payload_json += '"role":"user",'
            payload_json += '"content":"Analyze this response and suggest security tests:\\n' + escaped_response_data + '"'
            payload_json += '}'
            payload_json += ']'
            payload_json += '}'

            self.safe_append_text("Payload JSON string created.\n")
            return payload_json
        except Exception, e:
            traceback_str = traceback.format_exc()
            self.safe_append_text("Exception in create_payload: " + str(e) + "\nTraceback:\n" + traceback_str + "\n")
            raise e  # Re-raise exception to be caught in analyze_with_openai

    def escape_string(self, s):
        try:
            if not isinstance(s, str):
                s = unicode(s)  # Convert non-strings to strings
            # Escape backslashes, double quotes, and control characters
            s = s.replace('\\', '\\\\')
            s = s.replace('"', '\\"')
            s = s.replace('\n', '\\n')
            s = s.replace('\r', '\\r')
            s = s.replace('\t', '\\t')
            return s
        except Exception, e:
            self.safe_append_text("Exception in escape_string: " + str(e) + "\n")
            traceback_str = traceback.format_exc()
            self.safe_append_text("Traceback:\n" + traceback_str + "\n")
            raise e

    def parse_openai_response(self, response):
        try:
            self.safe_append_text("Parsing OpenAI response...\n")
            # Since we cannot use the json module, parse the JSON manually
            response_str = str(response)
            self.safe_append_text("OpenAI raw response: " + response_str + "\n")
            # Find the "content" field in the JSON response
            pattern = r'"content"\s*:\s*"([^"]*)"'
            match = re.search(pattern, response_str, re.DOTALL)
            if match:
                content = match.group(1)
                # Unescape any escaped characters
                content = content.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
                self.safe_append_text("Parsed content from OpenAI response.\n")
                return content
            else:
                self.safe_append_text("Failed to parse 'content' from OpenAI response.\n")
                return "Failed to parse OpenAI response"
        except Exception, e:
            self.safe_append_text("Failed to parse OpenAI response: " + str(e) + "\n")
            traceback_str = traceback.format_exc()
            self.safe_append_text("Traceback:\n" + traceback_str + "\n")
            return "Failed to parse OpenAI response"