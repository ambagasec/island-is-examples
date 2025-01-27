public static class Example {

    KeyStore trustStore;

    public boolean validateSaml(final String samlString, final String userIP,
    final String userAgent, final String authId)
    {
        boolean ok = false;
        try {
            SignableSAMLObject signedObject = (SignableSAMLObject)this.unmarshall(samlString);
            if (signedObject != null)
            {
                SignableSAMLObject samlObject =
                    (SignableSAMLObject)this.validateSignature(signedObject, trustStore);
                if (samlObject != null)
                {
                    Assertion assertion = this.getAssertion((Response)samlObject, userIP, false);
                    if (assertion!=null) {
                        final DateTime serverDate = new DateTime();
                        if (assertion.getConditions().getNotBefore().isAfter(serverDate)) {
                            throw new Exception("Token date valid yet (getNotBefore = "
                                    + assertion.getConditions().getNotBefore()
                                    + " ), server_date: " + serverDate);
                        }
                        if (assertion.getConditions().getNotOnOrAfter().isBefore(serverDate)) {
                            throw new Exception("Token date expired (getNotOnOrAfter = "
                                    + assertion.getConditions().getNotOnOrAfter()
                                    + " ), server_date: " + serverDate);
                        }
                        // Validate the assertions for IP, useragent and authId.
                        validateAssertion(assertion, userIP, userAgent, authId);
                        ok = true;
                    }
                }
            }
        } catch (Exception e) {
            //SAML not verified
            e.printStackTrace();
        }
        return ok;
    }

    //Unmarshall SAML string
    private final XMLObject unmarshall(final String samlString) throws Exception {
        try {
            byte[] samlToken = Base64.base64ToByteArray(samlString);
            final BasicParserPool ppMgr = new BasicParserPool();
            final HashMap<String, Boolean> features = new HashMap<String, Boolean>();
            features.put(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
            ppMgr.setBuilderFeatures(features);
            ppMgr.setNamespaceAware(true);
            Document document = ppMgr.parse(new ByteArrayInputStream(samlToken));
            if (document != null){
                final Element root = document.getDocumentElement();
                final UnmarshallerFactory unmarshallerFact = Configuration.getUnmarshallerFactory();
                if (unmarshallerFact != null && root != null)
                {
                    final Unmarshaller unmarshaller =
                        unmarshallerFact.getUnmarshaller(root);
                    try {
                        return unmarshaller.unmarshall(root);
                    } catch (NullPointerException e){
                        throw new Exception("NullPointerException", e);
                    }
                } else {
                    throw new Exception("NullPointerException : unmarshallerFact or root is null");
                }
            } else {
                throw new Exception("NullPointerException : document is null");
            }
        } catch (XMLParserException e) {
            throw new Exception(e);
        } catch (UnmarshallingException e) {
            throw new Exception(e);
        } catch (NullPointerException e) {
            throw new Exception(e);
        }
    }

    private final SAMLObject validateSignature(final SignableSAMLObject tokenSaml, KeyStore keyStore) throws Exception {
        try {
            // Validate structure signature
            final SAMLSignatureProfileValidator sigProfValidator =
                new SAMLSignatureProfileValidator();
            try {
                // Indicates signature id conform to SAML Signature profile
                sigProfValidator.validate(tokenSaml.getSignature());
            } catch (ValidationException e) {
                //ValidationException: signature isn't conform to SAML Signature
                profile.
                    throw new Exception(e);
            }
            String aliasCert = null;
            X509Certificate certificate;
            final KeyInfo keyInfo = tokenSaml.getSignature().getKeyInfo();
            final org.opensaml.xml.signature.X509Certificate xmlCert = keyInfo
                .getX509Datas().get(0).getX509Certificates().get(0);
            final CertificateFactory certFact = CertificateFactory
                .getInstance("X.509");
            final ByteArrayInputStream bis = new ByteArrayInputStream(Base64.
                    base64ToByteArray(xmlCert.getValue()));
            final X509Certificate cert = (X509Certificate) certFact
                .generateCertificate(bis);
            // Exist only one certificate
            final BasicX509Credential entityX509Cred = new BasicX509Credential();
            entityX509Cred.setEntityCertificate(cert);
            try {
                cert.checkValidity();
            }
            catch (CertificateExpiredException exp) {
                throw new Exception("Certificate expired.");
            }
            catch (CertificateNotYetValidException exp) {
                throw new Exception("Certificate not yet valid.");
            }
            boolean trusted = false;
            for (final Enumeration<String> e = keyStore.aliases(); e.hasMoreElements();)
            {
                aliasCert = e.nextElement();
                certificate = (X509Certificate) keyStore.getCertificate(aliasCert);
                try {
                    cert.verify(certificate.getPublicKey());
                    trusted = true;
                    break;
                }
                catch (Exception ex) {
                    //Do nothing - cert not trusted yet
                }
            }
            if (!trusted)
                throw new Exception("Certificate is not trusted.");
            else {
                if (cert.getSubjectDN().toString().contains("SERIALNUMBER=6503760649")
                     && cert.getIssuerDN().toString().startsWith("CN=Traustur bunadur"))
                        trusted = true;
                else {
                    throw new Exception("Certificate is not trusted.");
                }
            }
            // Validate signature
            final SignatureValidator sigValidator = new SignatureValidator(
                    entityX509Cred);
            sigValidator.validate(tokenSaml.getSignature());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return tokenSaml;
    }

    private Assertion getAssertion(final Response samlResponse,
            final String userIP, final boolean ipValidate) throws Exception {
        if (samlResponse.getAssertions() == null
                || samlResponse.getAssertions().isEmpty()) {
            //Assertion is null or empty
            return null;
                }
        final Assertion assertion = (Assertion)
            samlResponse.getAssertions().get(0);
        for (final Iterator<SubjectConfirmation> iter = assertion.getSubject().getSubjectConfirmations().iterator(); iter.hasNext();) {
            final SubjectConfirmation element = iter.next();
            final boolean isBearer = SubjectConfirmation.METHOD_BEARER.equals(element.getMethod());
            if (ipValidate) {
                if (isBearer) {
                    if (StringUtils.isBlank(userIP)) {
                        throw new Exception("browser_ip is null or empty.");
                    } else if (StringUtils.isBlank(element
                                .getSubjectConfirmationData().getAddress())) {
                        throw new Exception("token_ip attribute is null or empty.");
                                }
                }
                final boolean ipEqual = element.getSubjectConfirmationData()
                    .getAddress().equals(userIP);
                // Validation ipUser
                if (!ipEqual && ipValidate) {
                    throw new Exception("IPs doesn't match : token_ip ("
                            + element.getSubjectConfirmationData().getAddress()
                            + ") browser_ip (" + userIP + ")");
                }
            }
        }
        return assertion;
    }

    /**
     * Validate assertions for IP, user agent and auth ID
     * @param assertion The assertion to validate
     * @param ip The user IP
     * @param ua The users user agent
     * @param authId The auth ID
     * @throws Exception
     */
    private void validateAssertion(final Assertion assertion, String ip, String ua, String authId ) throws Exception {
        final List<XMLObject> listExtensions = assertion.getOrderedChildren();
        boolean find = false;
        AttributeStatement requestedAttr = null;
        // Search the attribute statement.
        for (int i = 0; i < listExtensions.size() && !find; i++) {
            final XMLObject xml = listExtensions.get(i);
            if (xml instanceof AttributeStatement) {
                requestedAttr = (AttributeStatement) xml;
                find = true;
            }
        }
        if (!find) {
            throw new Exception ("AttributeStatement it's not present.");
        }
        final List<Attribute> reqAttrs = requestedAttr.getAttributes();

        String attributeName, tempValue;
        XMLObject xmlObj;
        boolean ipOk = false, uaOk = false, authIdOk = false;

        // Process the attributes.
        for (int nextAttribute = 0; nextAttribute < reqAttrs.size(); nextAttribute++) {
            final Attribute attribute = reqAttrs.get(nextAttribute);
            attributeName = attribute.getName();
            if (attributeName.equals("IPAddress"))
            {
                xmlObj = attribute.getOrderedChildren().get(0);
                tempValue = ((XSStringImpl) xmlObj).getValue();
                ipOk = tempValue.equals(ip);
            }
            if (attributeName.equals("UserAgent"))
            {
                xmlObj = attribute.getOrderedChildren().get(0);
                tempValue = ((XSStringImpl) xmlObj).getValue();
                uaOk = tempValue.equals(ua);
            }
            if (attributeName.equals("AuthID"))
            {
                xmlObj = attribute.getOrderedChildren().get(0);
                tempValue = ((XSStringImpl) xmlObj).getValue();
                authIdOk = tempValue.equals(ip);
            }
        }
        if (ipOk || authIdOk || uaOk)
            System.out.println("Assertion valid.");
        else
            throw new Exception(
                String.format("Assertions not valid. IP valid %b, "
                    + "user agent" valid %b, auth ID valid %b",
                    ipOk, uaOk, authIdOk));
    }
}
