package intf;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public interface ISignatureVerifier {
	//Enveloping signature - meaning payload is enclosed within 'Signature' element

	//DOM based signing. DOM reads the entire xml in memory and thus xml file size is limited by heap size. 
	//JDK supports DOM based XML signing 
	public boolean verifySignature(String signedXmlFile) throws Exception;
	public boolean verifySignature(String signedXmlFile, PublicKey sigPublicKey) throws Exception;
	public boolean verifySignature(String signedXmlFile, X509Certificate sigCert) throws Exception;
    
    //for signature verification, streaming based API can be used to sign very large XML file.
	public boolean verifySignatureStreaming(String signedXmlFile) throws Exception;
	public boolean verifySignatureStreaming(String signedXmlFile, PublicKey sigPublicKey) throws Exception;
	public boolean verifySignatureStreaming(String signedXmlFile, X509Certificate sigCert) throws Exception;
	
	public boolean getVerificationFlag();
}
