<?php

function verifySaml()
{
    include 'xmlseclibs.php';
    $token = $_POST["token"];
    if ($token != NULL)
    {
        $xmlDoc = new DOMDocument();
        $saml = base64_decode($token);
        $xmlDoc->loadXML($saml);
        $xmlsec = new XMLSecurityDSig();
        $objXMLSecDSig = new XMLSecurityDSig();

        $objDSig = $objXMLSecDSig->locateSignature($xmlDoc);

        if ($objDSig == NULL) {
            throw new Exception("Cannot locate Signature Node");
        }
        $objXMLSecDSig->canonicalizeSignedInfo();
        $objXMLSecDSig->idKeys = array('ID');
        $objXMLSecDSig->idNS = array('wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
        $retVal = $objXMLSecDSig->validateReference();

        if ($retVal == NULL) {
            throw new Exception("Reference Validation Failed");
        }

        if (!VerifyDate($xmlDoc))
        {
            throw new Exception("Conditions not valid.");
        }

        // Ekki treystandi
        /*if (!verifyConditions($xmlDoc, get_client_ip()))
        {
        throw new Exception("Invalid client ip.");
        }*/

        $objKey = $objXMLSecDSig->locateKey();
        if (! $objKey ) {
            throw new Exception("Key not found");
        }
        $key = NULL;

        $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
        if (!verifyCert($objKeyInfo))
        {
            throw new Exception("Certificate not valid");
        }

        if (! $objKeyInfo->key && empty($key)) {
            $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE);
        }

        if (!$objXMLSecDSig->verify($objKey)) {
            throw new Exception("Signature invalid!");
        }
        else {
            checkUserAgent($xmlDoc, get_user_agent());
            checkIP($xmlDoc, get_client_ip());
            checkAuthID($xmlDoc, get_auth_id());
            return "Signature valid.";
        }
    }
}

function locateConditions($doc)
{
    $xpath = new DOMXPath($doc);
    $xpath->registerNamespace('assertion', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $nodeset = $xpath->query(".//assertion:Assertion/assertion:Conditions", $doc);
    return $nodeset->item(0);
}

function locateSubjectConfirmation($doc)
{
    $xpath = new DOMXPath($doc);
    $xpath->registerNamespace('assertion', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $nodeset = $xpath->query(".//assertion:Assertion/assertion:Subject/assertion:SubjectConfirmation/assertion:SubjectConfirmationData", $doc);
    return $nodeset->item(0);
}

function verifyConditions($doc, $ip)
{
    $conditions = locateSubjectConfirmation($doc);
    if (!$conditions)
    {
        throw new Exception("Unable to locate Conditions");
        return false;
    }
    try
    {
        $address = $conditions->getAttribute('Address');
    }
    catch (Exception $e)
    {
        throw new Exception("Exception while locating address");
        return false;
    }
    if (!strcmp($ip, "::1"))
        $ip = "127.0.0.1";
    if (strcmp($address, $ip))
    {
        throw new Exception("Invalid IP address.");
        return false;
    }
    else
        return true;
}

function VerifyDate($doc)
{
    try
    {
        $conditions = locateConditions($doc);
    }
    catch (Exception $e)
    {
        throw new Exception("Exception while locating Conditions");
        return false;
    }
    if (!$conditions)
    {
        throw new Exception("Unable to locate Conditions");
        return false;
    }
    try
    {
        $start = $conditions->getAttribute('NotBefore');
        $end = $conditions->getAttribute('NotOnOrAfter');
    }
    catch (Exception $e)
    {
        throw new Exception("Exception while locating start or end");
        return false;
    }
    if (!$start || !$end)
    {
        throw new Exception("Unable to locate start (NotBefore) or end (NotOnOrAfter)");
        return false;
    }
    date_default_timezone_set('Atlantic/Reykjavik');
    $startTime = strtotime($start);
    $endTime = strtotime($end);

    if (!is_int($startTime) || !is_int($endTime))
    {
        throw new Exception("Unable to get time from start (NotBefore) or end
            (NotOnOrAfter)");
        return false;
    }
    $now = date(time());

    $inSpan = $startTime < $now && $now < $endTime;

    if (!$inSpan)
    {
        throw new Exception("Response is not within specified timeframe");
        return false;
    }
    return true;
}

function verifyCert($objKeyInfo)
{
    $caFile = file_get_contents("TrausturBunadur.pem");
    $caCert = openssl_x509_read($caFile);
    $caCertParsed = openssl_x509_parse($caCert, true);
    $parsed = openssl_x509_parse($objKeyInfo->getX509Certificate());

    date_default_timezone_set('Atlantic/Reykjavik');
    $dateFrom = date($parsed['validFrom_time_t']);
    $dateTo = date($parsed['validTo_time_t']);
    $nowTime = date(time());
    if ($nowTime < $dateFrom || $nowTime > $dateTo)
    {
        throw new Exception("Certificate expired or not valid yet");
    }

    $kennitala = $parsed['subject']['serialNumber'];
    $issuer = $parsed['issuer']['CN'];

    if ($kennitala != "6503760649")
    {
        throw new Exception("Ekki rétt kennitala í undirritunarskilríki");
        return false;
    }

    if ($issuer!= "Traustur bunadur")
    {
        throw new Exception("Ekki réttur útgefandi undirritunarskilríkis");
        return false;
    }

    $subjectKey = $caCertParsed['extensions']['subjectKeyIdentifier'];
    $authKey = $parsed['extensions']['authorityKeyIdentifier'];
    $authKey = str_replace('keyid:', '', $authKey);
    if (!strcasecmp($subjectKey, $authKey))
    {
        throw new Exception("Not correct CA");
        return false;
    }

    return true;
}

//Athugið að treysta ekki eingöngu þessu prófi
function checkIP($xmlDoc, $ip)
{
    if ($xmlDoc != NULL)
    {
        if (!strcmp($ip, "::1"))
            $ip = "127.0.0.1";
        $searchNode = $xmlDoc->getElementsByTagName( "Attribute" );

        foreach( $searchNode as $attribute )
        {
            $friendly = $attribute->getAttribute("FriendlyName");
            if ($friendly == "IPTala")
            {
                if ($attribute->nodeValue == $ip)
                    echo "IP OK <br>";
                else
                    echo "IP not OK <br>";
                break;
            }
        }
    }
}

function checkUserAgent($xmlDoc, $ua)
{
    if ($xmlDoc != NULL)
    {
        $searchNode = $xmlDoc->getElementsByTagName( "Attribute" );
        foreach( $searchNode as $attribute )
        {
            $friendly = $attribute->getAttribute("FriendlyName");
            if ($friendly == "NotandaStrengur")
            {
                if ($attribute->nodeValue == $ua)
                    echo "User agent OK <br>";
                else
                    echo "User agent not OK <br>";
                break;
            }
        }
    }
}

function checkAuthID($xmlDoc, $authid)
{
    if ($xmlDoc != NULL)
    {
        $searchNode = $xmlDoc->getElementsByTagName( "Attribute" );
        foreach( $searchNode as $attribute )
        {
            $friendly = $attribute->getAttribute("FriendlyName");
            if ($friendly == "AuðkenningarNúmer")
            {
                if ($attribute->nodeValue == $authid)
                    echo "Auth ID OK <br>";
                else
                    echo "Auth ID not OK <br>";
                break;
            }
        }
    }
}

function get_client_ip() {
    $ipaddress = '';
    if (!empty($_SERVER['HTTP_CLIENT_IP']))
        $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
    else if(!empty($_SERVER['HTTP_X_FORWARDED_FOR']))
        $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
    else if(!empty($_SERVER['HTTP_X_FORWARDED']))
        $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
    else if(!empty($_SERVER['HTTP_FORWARDED_FOR']))
        $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
    else if(!empty($_SERVER['HTTP_FORWARDED']))
        $ipaddress = $_SERVER['HTTP_FORWARDED'];
    else if(!empty($_SERVER['REMOTE_ADDR']))
        $ipaddress = $_SERVER['REMOTE_ADDR'];
    else
        $ipaddress = 'UNKNOWN';
    return $ipaddress;
}

function get_user_agent()
{
    $useragent = '';
    if (!empty($_SERVER['HTTP_USER_AGENT']))
        $useragent = $_SERVER['HTTP_USER_AGENT'];
    return $useragent;
}

//Þetta þarf að útfæra sérstaklega ef notað er authId
function get_auth_id()
{
    return "1234567890";
}

?>
