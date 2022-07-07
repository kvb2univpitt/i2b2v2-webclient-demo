<?php

$host = filter_input(INPUT_SERVER, 'HTTP_HOST', FILTER_UNSAFE_RAW);
$port = filter_input(INPUT_SERVER, 'SERVER_PORT', FILTER_UNSAFE_RAW);

$pmURL = "http://127.0.0.1:8080/i2b2/rest/PMService/getServices";
$pmCheckAllRequests = false;

$WHITELIST = array(
    'http' . (($port == '443') ? 's' : '' ) . "://" . $host,
    'http://127.0.0.1',
    'http://services.i2b2.org',
);

$BLACKLIST = array(
    "http://127.0.0.1:9090/test",
    "http://localhost:9090/test",
    "http://i2b2-core-server-saml-demo:9090/test"
);

// There is nothing to configure below this line

$pm_cell_urls = array();
$i2b2_config_data = json_decode(file_get_contents("i2b2_config_domains.json"), true);
if ($i2b2_config_data) {
    foreach ($i2b2_config_data['lstDomains'] as $domain) {
        $pm_cell_urls[] = $domain['urlCellPM'];
    }
}

$regex = "/(http|https)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,5}(\:[0-9]{2,5})*\/?/";
foreach ($pm_cell_urls as $match) {
    // match hostname
    if (preg_match($regex, $match, $url)) {
        array_push($WHITELIST, $url[0]);
    }
}

$post_body = file_get_contents("php://input");
if (!empty($post_body)) {
    // Process the POST for proxy redirection
    // Validate that POST data is XML and extract <proxy> tag
    $startPos = strpos($post_body, "<redirect_url>") + 14;
    $endPos = strpos($post_body, "</redirect_url>", $startPos);
    $proxyURL = substr($post_body, $startPos, ($endPos - $startPos));
    $newXML = $post_body;

    // Do not allow DOCTYPE declarations
    $replace_match = '/^.*(?:!DOCTYPE).*$(?:\r\n|\n)?/m';
    if (preg_match($replace_match, $newXML)) {
        exit('DOCTYPE not allowed to be proxied');
    }

    if ($pmCheckAllRequests) {
        error_log("Searhing for Security in " . $post_body);
        //Validate that user is valid against known PM

        preg_match("/<security(.*)?>(.*)?<\/security>/", $post_body, $proxySecurity);

        error_log("My Security is " . $proxySecurity[1]);
        preg_match("/<domain(.*)?>(.*)?<\/domain>/", $proxySecurity[0], $proxyDomain);
        preg_match("/<username(.*)?>(.*)?<\/username>/", $proxySecurity[0], $proxyUsername);
        preg_match("/<password(.*)?>(.*)?<\/password>/", $proxySecurity[0], $proxyPassword);

        $checkPMXML = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><i2b2:request xmlns:i2b2=\"http://www.i2b2.org/xsd/hive/msg/1.1/\" xmlns:pm=\"http://www.i2b2.org/xsd/cell/pm/1.1/\"> <message_header> <i2b2_version_compatible>1.1</i2b2_version_compatible> <hl7_version_compatible>2.4</hl7_version_compatible> <sending_application> <application_name>i2b2 Project Management</application_name> <application_version>1.1</application_version> </sending_application> <sending_facility> <facility_name>i2b2 Hive</facility_name> </sending_facility> <receiving_application> <application_name>Project Management Cell</application_name> <application_version>1.1</application_version> </receiving_application> <receiving_facility> <facility_name>i2b2 Hive</facility_name> </receiving_facility> <datetime_of_message>2007-04-09T15:19:18.906-04:00</datetime_of_message> <security> " . $proxyDomain[0] . $proxyUsername[0] . $proxyPassword[0] . " </security> <message_control_id> <message_num>0qazI4rX6SDlQlk46wqQ3</message_num> <instance_num>0</instance_num> </message_control_id> <processing_id> <processing_id>P</processing_id> <processing_mode>I</processing_mode> </processing_id> <accept_acknowledgement_type>AL</accept_acknowledgement_type> <application_acknowledgement_type>AL</application_acknowledgement_type> <country_code>US</country_code> <project_id>undefined</project_id> </message_header> <request_header> <result_waittime_ms>180000</result_waittime_ms> </request_header> <message_body> <pm:get_user_configuration> <project>undefined</project> </pm:get_user_configuration> </message_body></i2b2:request>";
        // Process the POST for proxy redirection



        error_log($checkPMXML, 0);
        error_log("My proxy: " . $proxyURL, 0);
    }

    // ---------------------------------------------------
    //   white-list processing on the URL
    // ---------------------------------------------------
    $isAllowed = false;
    $requestedURL = strtoupper($proxyURL);
    foreach ($WHITELIST as $entryValue) {
        $checkValue = strtoupper(substr($requestedURL, 0, strlen($entryValue)));
        if ($checkValue == strtoupper($entryValue)) {
            $isAllowed = true;
            break;
        }
    }
    if (!$isAllowed) {
        // security as failed - exit here and don't allow one more line of execution the opportunity to reverse this
        die("The proxy has refused to relay your request.");
    }
    // ---------------------------------------------------
    //   black-list processing on the URL
    // ---------------------------------------------------
    foreach ($BLACKLIST as $entryValue) {
        $checkValue = strtoupper(substr($requestedURL, 0, strlen($entryValue)));
        if ($checkValue == strtoupper($entryValue)) {
            // security as failed - exit here and don't allow one more line of execution the opportunity to reverse this
            die("The proxy has refused to relay your request.");
        }
    }

    if ($pmCheckAllRequests) {
        // open the URL and forward the new XML in the POST body
        $proxyRequest = curl_init($pmURL);

        // these options are set for hyper-vigilance purposes
        curl_setopt($proxyRequest, CURLOPT_COOKIESESSION, 0);
        curl_setopt($proxyRequest, CURLOPT_FORBID_REUSE, 1);
        curl_setopt($proxyRequest, CURLOPT_FRESH_CONNECT, 0);
        // Specify NIC to use for outgoing connection, fixes firewall+DMZ headaches
        // curl_setopt($proxyRequest, CURLOPT_INTERFACE, "XXX.XXX.XXX.XXX");
        // other options
        curl_setopt($proxyRequest, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($proxyRequest, CURLOPT_CONNECTTIMEOUT, 900);        // wait 15 minutes
        // data to proxy thru
        curl_setopt($proxyRequest, CURLOPT_POST, 1);
        curl_setopt($proxyRequest, CURLOPT_POSTFIELDS, $checkPMXML);
        // SEND REQUEST!!!
        curl_setopt($proxyRequest, CURLOPT_HTTPHEADER, array('Expect:', 'Content-Type: text/xml'));
        $proxyResult = curl_exec($proxyRequest);
        // cleanup cURL connection
        curl_close($proxyRequest);
        error_log("My PM Result " . $proxyResult);

        $pattern = "/<status type=\"ERROR\">/i";
        //Check if request is valid
        if (preg_match($pattern, $proxyResult)) {
            error_log("Local PM denied request");
            die("Local PM server could not validate the request.");
        }
    }

    // open the URL and forward the new XML in the POST body
    $proxyRequest = curl_init($proxyURL);

    curl_setopt($proxyRequest, CURLOPT_SSL_VERIFYPEER, FALSE);
    // these options are set for hyper-vigilance purposes
    curl_setopt($proxyRequest, CURLOPT_COOKIESESSION, 0);
    curl_setopt($proxyRequest, CURLOPT_FORBID_REUSE, 1);
    curl_setopt($proxyRequest, CURLOPT_FRESH_CONNECT, 0);
    // Specify NIC to use for outgoing connection, fixes firewall+DMZ headaches
    // curl_setopt($proxyRequest, CURLOPT_INTERFACE, "XXX.XXX.XXX.XXX");  
    // other options
    curl_setopt($proxyRequest, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($proxyRequest, CURLOPT_CONNECTTIMEOUT, 900);  // wait 15 minutes
    // data to proxy thru
    curl_setopt($proxyRequest, CURLOPT_POST, 1);
    curl_setopt($proxyRequest, CURLOPT_POSTFIELDS, $newXML);
    // SEND REQUEST!!!
    $headers = array('Expect:', 'Content-Type: text/xml');
    foreach ($_SERVER as $key => $value) {
        if (substr($key, 0, 4) === "AJP_") {
            $header = str_replace('AJP_', 'X-', $key) . ": " . $value;
            array_push($headers, $header);
        }
    }

    curl_setopt($proxyRequest, CURLOPT_HTTPHEADER, $headers);
//    curl_setopt($proxyRequest, CURLOPT_HTTPHEADER, array('Expect:', 'Content-Type: text/xml'));
    $proxyResult = curl_exec($proxyRequest);
    // cleanup cURL connection
    curl_close($proxyRequest);

    // perform any analysis or processing on the returned result here
    header("Content-Type: text/xml", true);
    print($proxyResult);
}