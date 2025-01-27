using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Serialization;

public static bool verifySamlSimple(string samlString, string ip, string ua, string authId, out string message)
{
    message = "";
    XmlDocument doc = new XmlDocument();
    doc.PreserveWhitespace = true;
    doc.LoadXml(samlString);

    SignedXml signedXml = new SignedXml(doc);
    //Sækjum undirritun og skoðum
    XmlNodeList nodeList = doc.GetElementsByTagName("Signature");
    XmlNodeList certList = doc.GetElementsByTagName("X509Certificate");
    signedXml.LoadXml((XmlElement)nodeList[0]);
    byte[] certData = Encoding.Default.GetBytes(certList[0].InnerText);
    X509Certificate2 cert = new X509Certificate2(certData);

    //Hér er mikilvægt að setja ekki true í seinna gildi nema útfærð sé
    //aðgerð sem sannreynir gildi skilríkis sérstaklega
    bool signatureOk = signedXml.CheckSignature(cert, false);
    if (signatureOk)
        message = "Signature OK. ";
    else
        message = "Signature not OK. ";

    bool certOk = false;
    if (cert.Issuer.StartsWith("CN=Traustur bunadur") &&
            cert.Subject.Contains("SERIALNUMBER=6503760649"))
    {
        certOk = true;
        message += "Certificate is OK. ";
    }
    else
        message += "Certificate not OK. ";

    DateTime nowTime = DateTime.UtcNow;
    //Sækjum tíma í Conditions og berum saman
    XmlNodeList condNodeList = doc.GetElementsByTagName("Conditions");
    DateTime fromTime =
        DateTime.Parse(condNodeList[0].Attributes["NotBefore"].Value);
    DateTime toTime =
        DateTime.Parse(condNodeList[0].Attributes["NotOnOrAfter"].Value);

    bool timeOk = false;
    if (nowTime > fromTime && toTime > nowTime)
    {
        timeOk = true;
        message += "SAML time valid. ";
    }
    else if (nowTime < fromTime)
        message += "From time has not passed yet. ";
    else if (nowTime > toTime)
        message += "To time has passed. ";

    //Skoðum nú IP tölu notanda, notandastreng og auth id úr Attributes
    bool ipOk = false;
    bool uaOk = false;
    bool authidOk = false;
    XmlNodeList attrList =
        doc.GetElementsByTagName("Attribute");
    if (attrList.Count > 0)
    {
        foreach (XmlNode attrNode in attrList)
        {
            XmlAttributeCollection attrCol = attrNode.Attributes;
            //Staðfestum að IP tala sé sú sama – athugið að ekki er
            //alltaf hægt að treysta á að IP tala sé sú sama
            if (attrCol["Name"].Value.Equals("IPAddress"))
            {
                ipOk = attrNode.FirstChild.InnerText.Equals(ip);
                message += "Correct client IP. ";
            }
            //Staðfestum að user agent strengur sé sá sami
            if (attrCol["Name"].Value.Equals("UserAgent"))
            {
                uaOk = attrNode.FirstChild.InnerText.Equals(ua);
                message += "Correct client user agent. ";
            }
            //Staðfestum að auðkenningarnúmer sé það sama
            if (attrCol["Name"].Value.Equals("AuthID"))
            {
                authidOk =
                    attrNode.FirstChild.InnerText.Equals(authId);
                message += "Correct client auth ID. ";
            }
        }
        if (!ipOk)
            message += "Incorrect client IP. ";
        if (!uaOk)
            message += "Incorrect client user agent. ";
        if (!uaOk)
            message += "Incorrect auth ID. ";
    }
    else
        message += "No Attributes found";

    // Skeytið er í lagi ef undirritun, skilríki, tímar eru í lagi
    // ásamt ip-tölu, notandastreng eða auðkenningarnúmer.
    return signatureOk && certOk && timeOk &&
        (ipOk || uaOk || authidOk);
}
