package fatca.intf;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public interface ISignerNonXml {
	//wraps text file in <Wrapper> xml tag and sign
    public boolean wrapTextFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    public boolean wrapTextFileInXmlAndSignStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
	
	//wraps base64 encoded binary content in <Wrapper> xml tag and sign
    public boolean wrapBinaryFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    public boolean wrapBinaryFileInXmlAndSignStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;

    //for wrapped text and/or binary signing
    //<Wrapper xmlns="urn:xmpp:xml-element" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd">
    //xsi:schemaLocation="urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd 
    public String getWrapperXsiSchemaLoc();
    //flag indicating if 'Wrapper' 'schemaLocation' attribute would be present or not 
    public void setWrapperXsiSchemaLoc(boolean val);
    //flag indicating if 'Wrapper' 'schemaLocation' attribute would be present or not - default false
    public boolean isWrapperXsiSchemaLoc();
    //'Wrapper' 'schemaLocation' attribute value if flag is set too true 
    public void setWrapperXsiSchemaLoc(String val);
    //flag indicating if 'Wrapper' 'xmlns:xsi' attribute would be present or not 
    public boolean isWrapperXsi();
    public void setWrapperXsi(boolean val);
    //<Wrapper xmlns="urn:xmpp:xml-element" ....> OR <ns1:Wrapper xmlns:ns1="urn:xmpp:xml-element" ....> 
    public String getWrapperPrefix();
    public void setWrapperPrefix(String prefix);
    //'Wrapper' namespace - default to 'urn:xmpp:xml-element'
    public String getWrapperNS();
    public void setWrapperNS(String ns);

	//not used in FATCA. Sign a text file with no transformation - DOM based signing
    public boolean signTextFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    //not used in FATCA. Sign a binary file with BINARY transformation - DOM based signing
    public boolean signBinaryFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    //not used in FATCA. Sign a text file with no transformation - streaming based signing
    public boolean signTextFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    //not used in FATCA. Sign a binary file with BINARY transformation - streaming based signing
    public boolean signBinaryFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
}
