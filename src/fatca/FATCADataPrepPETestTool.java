package fatca;

import fatca.impl.FATCAPackager;
import fatca.intf.IPackager;
import fatca.intf.IPackager.MetadataBinaryEncoding;
import fatca.intf.IPackager.MetadataFileFormat;
import fatca.intf.ISigner;
import fatca.util.UtilShared;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;



/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public class FATCADataPrepPETestTool {
	protected Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	protected String receiverPublicCertName = "Certs/000000.00000.TA.840.crt";
	
	protected IPackager pkgr = new FATCAPackager();
	protected ISigner signer = pkgr.getSigner();
	
	protected String defaultConfigFile = "ConfigAndCmds.txt";
	protected class Cmd {
		public String cmdStr;
		public HashMap<String, String> hashCmdArgs = new HashMap<String, String>();
	}
	
	private void readConfigAndExceuteCommands() throws Exception {
		readConfigAndExceuteCommands(defaultConfigFile);
	}
	
	protected X509Certificate receiverPublicCert=null, senderPublicCert=null, approverPublicCert=null;
	protected PrivateKey receiverPrivateKey=null, senderPrivateKey=null, approverPrivateKey=null;
	protected String senderGiin=null, receiverGiin=null, approverGiin=null;
	
	protected void readConfigAndExceuteCommands(String conf) throws Exception {
		try {
			String senderPrivateKSType, senderPublicKSType, receiverPrivateKSType, receiverPublicKSType, approverPrivateKSType, approverPublicKSType,
			senderPrivateKSFile=null, senderPublicKSFile=null, receiverPrivateKSFile=null, receiverPublicKSFile=null, approverPrivateKSFile=null, approverPublicKSFile=null,
			senderPrivateKSPwd, senderPublicKSPwd, receiverPrivateKSPwd, receiverPublicKSPwd, approverPrivateKSPwd, approverPublicKSPwd,
			senderPrivateKeyPwd=null, receiverPrivateKeyPwd=null, approverPrivateKeyPwd=null,
			senderPrivateKeyAlias=null, senderPublicKeyAlias=null, receiverPrivateKeyAlias=null, receiverPublicKeyAlias=null, approverPrivateKeyAlias=null, approverPublicKeyAlias=null;
			senderPrivateKSType=senderPublicKSType=receiverPrivateKSType=receiverPublicKSType=approverPrivateKSType=approverPublicKSType=IPackager.defaultKeystoreType;
			senderPrivateKSPwd=senderPublicKSPwd=receiverPrivateKSPwd=receiverPublicKSPwd=approverPrivateKSPwd=approverPublicKSPwd="pwd123";
			int taxyear = -1;
			ArrayList<Cmd> listCmds = new ArrayList<Cmd>();
			BufferedReader br = new BufferedReader(new FileReader(conf));
			String line, key, val, input=null, output=null;
			StringTokenizer st;
			int pos;
			Cmd cmd;
			boolean isComment = false, flag;
			while((line = br.readLine()) != null) {
				line = line.trim();
				if (line.startsWith("//") || line.startsWith("!"))
					continue;
				if (line.startsWith("/*") && !isComment) {
					isComment = true;
					continue;
				} else if (line.startsWith("*/") && isComment) {
					isComment = false;
					line = line.substring(2).trim();
				}
				if ("".equals(line) || isComment)
					continue;
				key = val = null; 
				st = new StringTokenizer(line, " =");
				if (!st.hasMoreTokens())
					continue;
				else {
					key = st.nextToken();
					if (st.hasMoreTokens())
						val = line.substring(key.length()+1).trim();
				}
				if ("senderPrivateKSType".equalsIgnoreCase(key))
					senderPrivateKSType = val;
				else if ("senderPublicKSType".equalsIgnoreCase(key))
					senderPublicKSType = val;
				else if ("receiverPrivateKSType".equalsIgnoreCase(key))
					receiverPrivateKSType = val;
				else if ("receiverPublicKSType".equalsIgnoreCase(key))
					receiverPublicKSType = val;
				else if ("approverPrivateKSType".equalsIgnoreCase(key))
					approverPrivateKSType = val;
				else if ("approverPublicKSType".equalsIgnoreCase(key))
					approverPublicKSType = val;
				else if ("senderPrivateKSFile".equalsIgnoreCase(key)) {
					senderPrivateKSFile = val;
					if (senderPrivateKSFile.endsWith(".jks"))
						senderPrivateKSType = "jks";
				}
				else if ("senderPublicKSFile".equalsIgnoreCase(key)) {
					senderPublicKSFile = val;
					if (senderPublicKSFile.endsWith(".jks"))
						senderPublicKSType = "jks";
				}
				else if ("receiverPrivateKSFile".equalsIgnoreCase(key)) {
					receiverPrivateKSFile = val;
					if (receiverPrivateKSFile.endsWith(".jks"))
						receiverPrivateKSType = "jks";
				}
				else if ("receiverPublicKSFile".equalsIgnoreCase(key)) {
					receiverPublicKSFile = val;
					if (receiverPublicKSFile.endsWith(".jks"))
						receiverPublicKSType = "jks";
				}
				else if ("approverPrivateKSFile".equalsIgnoreCase(key)) {
					approverPrivateKSFile = val;
					if (approverPrivateKSFile.endsWith(".jks"))
						approverPrivateKSType = "jks";
				}
				else if ("approverPublicKSFile".equalsIgnoreCase(key)) {
					approverPublicKSFile = val;
					if (approverPublicKSFile.endsWith(".jks"))
						approverPublicKSType = "jks";
				}
				else if ("senderPrivateKSPwd".equalsIgnoreCase(key))
					senderPrivateKSPwd = val;
				else if ("senderPublicKSPwd".equalsIgnoreCase(key))
					senderPublicKSPwd = val;
				else if ("receiverPublicCertName".equalsIgnoreCase(key))
					receiverPublicCertName = val;
				else if ("receiverPrivateKSPwd".equalsIgnoreCase(key))
					receiverPrivateKSPwd = val;
				else if ("receiverPublicKSPwd".equalsIgnoreCase(key))
					receiverPublicKSPwd = val;
				else if ("approverPrivateKSPwd".equalsIgnoreCase(key))
					approverPrivateKSPwd = val;
				else if ("approverPublicKSPwd".equalsIgnoreCase(key))
					approverPublicKSPwd = val;
				else if ("senderPrivateKeyPwd".equalsIgnoreCase(key))
					senderPrivateKeyPwd = val;
				else if ("receiverPrivateKeyPwd".equalsIgnoreCase(key))
					receiverPrivateKeyPwd = val;
				else if ("approverPrivateKeyPwd".equalsIgnoreCase(key))
					approverPrivateKeyPwd = val;
				else if ("senderPrivateKeyAlias".equalsIgnoreCase(key))
					senderPrivateKeyAlias = val;
				else if ("senderPublicKeyAlias".equalsIgnoreCase(key))
					senderPublicKeyAlias = val;
				else if ("receiverPrivateKeyAlias".equalsIgnoreCase(key))
					receiverPrivateKeyAlias = val;
				else if ("receiverPublicKeyAlias".equalsIgnoreCase(key))
					receiverPublicKeyAlias = val;
				else if ("approverPrivateKeyAlias".equalsIgnoreCase(key))
					approverPrivateKeyAlias = val;
				else if ("approverPublicKeyAlias".equalsIgnoreCase(key))
					approverPublicKeyAlias = val;
				else if ("senderGiin".equalsIgnoreCase(key))
					senderGiin = val;
				else if ("receiverGiin".equalsIgnoreCase(key))
					receiverGiin = val;
				else if ("approverGiin".equalsIgnoreCase(key))
					approverGiin = val;
				else if ("taxYear".equalsIgnoreCase(key))
					taxyear = Integer.parseInt(val);
				else {
					cmd = new Cmd();
					cmd.cmdStr = key;
					listCmds.add(cmd);
					if ("stop".equalsIgnoreCase(cmd.cmdStr))
						break;
					if (val != null) {
						st = new StringTokenizer(val);
						while(st.hasMoreTokens()) {
							val = st.nextToken();
							pos = val.indexOf('=');
							if (pos != -1)
								cmd.hashCmdArgs.put(val.substring(0,pos).toLowerCase(), val.substring(pos+1));
							else {
								cmd.hashCmdArgs.put(cmd.cmdStr, val);
								break;
							}
						}
					}
				}
			}
			br.close();
			if (receiverPublicKSType != null && receiverPublicKSFile != null && receiverPublicKSPwd != null)
				try{receiverPublicCert = UtilShared.getCert(receiverPublicKSType, receiverPublicKSFile, receiverPublicKSPwd, receiverPublicKeyAlias);} catch(Exception e) {}
			if (receiverPublicCert == null)
				try{receiverPublicCert = (X509Certificate)UtilShared.getCert(receiverPublicCertName);} catch(Exception e) {}
			if (senderPublicKSType != null && senderPublicKSFile != null && senderPublicKSPwd != null)
				try{senderPublicCert = UtilShared.getCert(senderPublicKSType, senderPublicKSFile, senderPublicKSPwd, senderPublicKeyAlias);} catch(Exception e) {}
			if (approverPublicKSType != null && approverPublicKSFile != null && approverPublicKSPwd != null)
				try{approverPublicCert = UtilShared.getCert(approverPublicKSType, approverPublicKSFile, approverPublicKSPwd, approverPublicKeyAlias);} catch(Exception e) {}
			if (senderPrivateKSType != null && senderPrivateKSFile != null && senderPrivateKeyPwd != null && senderPrivateKSPwd != null)
				try{senderPrivateKey = UtilShared.getPrivateKey(senderPrivateKSType, senderPrivateKSFile, senderPrivateKSPwd, senderPrivateKeyPwd, senderPrivateKeyAlias);} catch(Exception e) {}
			if (receiverPrivateKSType != null && receiverPrivateKSFile != null && receiverPrivateKeyPwd != null && receiverPrivateKSPwd != null)
				try{receiverPrivateKey = UtilShared.getPrivateKey(receiverPrivateKSType, receiverPrivateKSFile, receiverPrivateKSPwd, receiverPrivateKeyPwd, receiverPrivateKeyAlias);} catch(Exception e) {}
			if (approverPrivateKSType != null && approverPrivateKSFile != null && approverPrivateKeyPwd != null && approverPrivateKSPwd != null)
				try{approverPrivateKey = UtilShared.getPrivateKey(approverPrivateKSType, approverPrivateKSFile, approverPrivateKSPwd, approverPrivateKeyPwd, approverPrivateKeyAlias);} catch(Exception e) {}
			X509Certificate sigPublicCert; PrivateKey sigPrivateKey, sigVerifyCert;
			MetadataFileFormat fileFormat = null; MetadataBinaryEncoding binaryEncoding = null;
			for (int i = 0; i < listCmds.size(); i++) {
				cmd = listCmds.get(i);
				if ("stop".equalsIgnoreCase(cmd.cmdStr) || "exit".equalsIgnoreCase(cmd.cmdStr))
					break;
				if ("isWrapperXsi".equalsIgnoreCase(cmd.cmdStr)) {
					signer.setWrapperXsi("true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
					continue;
				}
				else if ("isWrapperXsiSchemaLoc".equalsIgnoreCase(cmd.cmdStr)) {
					signer.setWrapperXsiSchemaLoc("true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
					continue;
				}
				else if ("isXmlChunkStreaming".equalsIgnoreCase(cmd.cmdStr)) {
					signer.setXmlChunkStreaming("true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
					continue;
				}
				else if ("xmlChunkStreamingSize".equalsIgnoreCase(cmd.cmdStr)) {
					signer.setXmlChunkStreamingSize(Integer.parseInt(cmd.hashCmdArgs.get(cmd.cmdStr)));
					continue;
				}
				else if ("wrapperXsiSchemaLoc".equalsIgnoreCase(cmd.cmdStr)) {
					signer.setWrapperXsiSchemaLoc(cmd.hashCmdArgs.get(cmd.cmdStr));
					continue;
				}
				else if ("isValidateAllSignature".equalsIgnoreCase(cmd.cmdStr)) {
					pkgr.getSigner().setValidateAllSignature("true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
					continue;
				}
				else if ("wrapperNS".equalsIgnoreCase(cmd.cmdStr)) {
					signer.setWrapperNS(cmd.hashCmdArgs.get(cmd.cmdStr));
					continue;
				}
				else if ("wrapperPrefix".equalsIgnoreCase(cmd.cmdStr)) {
					signer.setWrapperPrefix(cmd.hashCmdArgs.get(cmd.cmdStr));
					continue;
				}
				else if ("signaturePrefix".equalsIgnoreCase(cmd.cmdStr)) {
					signer.setSignaturePrefix(cmd.hashCmdArgs.get(cmd.cmdStr));
					continue;
				} else if ("aesCipherOpMode".equalsIgnoreCase(cmd.cmdStr)) {
					pkgr.setAesCipherOpMode(cmd.hashCmdArgs.get(cmd.cmdStr));
					continue;
				} else if ("isDualModeDecryption".equalsIgnoreCase(cmd.cmdStr)) {
					pkgr.setDualModeDecryption("true".equalsIgnoreCase(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
					continue;
				} else if ("sigRefIdPos".equalsIgnoreCase(cmd.cmdStr)) {
					//Object|SignatureProperty|SignatureProperties
					pkgr.getSigner().setSigRefIdPos(cmd.hashCmdArgs.get(cmd.cmdStr));
					continue;
				} else if ("sigXmlTransform".equalsIgnoreCase(cmd.cmdStr)) {
					//Inclusive|InclusiveWithComments|Exclusive|ExclusiveWithComments|None
					pkgr.getSigner().setSigXmlTransform(cmd.hashCmdArgs.get(cmd.cmdStr));
					continue;
				}
				key = "input";
				if (cmd.hashCmdArgs.containsKey(key))
					input = cmd.hashCmdArgs.get(key);
				else
					input = cmd.hashCmdArgs.get(cmd.cmdStr);
				if (input == null)
					input = output;
				output = null;
				key = "output";
				if (cmd.hashCmdArgs.containsKey(key))
					output = cmd.hashCmdArgs.get(key);
				if (input == null) {
					logger.error("null input. line=" + line);
					continue;
				}
				// for metadata 1.1 - encryption and packaging
				fileFormat = null; binaryEncoding = null;
				key = "fileFormat".toLowerCase();
				if (cmd.hashCmdArgs.containsKey(key))
					fileFormat = getFileFormat(cmd.hashCmdArgs.get(key));
				key = "binaryEncoding".toLowerCase();
				if (cmd.hashCmdArgs.containsKey(key))
					binaryEncoding = getBinaryEncoding(cmd.hashCmdArgs.get(key));
				if ("signBinary".equalsIgnoreCase(cmd.cmdStr) || "signBinaryStreaming".equalsIgnoreCase(cmd.cmdStr) ||
						 "signXml".equalsIgnoreCase(cmd.cmdStr) || "signXmlStreaming".equalsIgnoreCase(cmd.cmdStr) ||
						"signText".equalsIgnoreCase(cmd.cmdStr) || "signTextStreaming".equalsIgnoreCase(cmd.cmdStr) ||
						"wrapBinaryInXmlAndSign".equalsIgnoreCase(cmd.cmdStr) || "wrapBinaryInXmlAndSignStreaming".equalsIgnoreCase(cmd.cmdStr) || 
						"wrapTextInXmlAndSign".equalsIgnoreCase(cmd.cmdStr) || "wrapTextInXmlAndSignStreaming".equalsIgnoreCase(cmd.cmdStr)) {
					if (output == null)
						output = input + ".signed.xml";
					sigPublicCert = senderPublicCert;
					sigPrivateKey = senderPrivateKey;
					key = "sigPublicCert".toLowerCase();
					if (cmd.hashCmdArgs.containsKey(key)) {
						val = cmd.hashCmdArgs.get(key);
						if ("senderPublicCert".equalsIgnoreCase(val) || "senderPubCert".equalsIgnoreCase(val))
							sigPublicCert = senderPublicCert;
						else if ("receiverPublicCert".equalsIgnoreCase(val) || "receiverPubCert".equalsIgnoreCase(val))
							sigPublicCert = receiverPublicCert;
						else if ("approverPublicCert".equalsIgnoreCase(val) || "approverPubCert".equalsIgnoreCase(val))
							sigPublicCert = approverPublicCert;
					}
					key = "sigKey".toLowerCase();
					if (cmd.hashCmdArgs.containsKey(key)) {
						val = cmd.hashCmdArgs.get(key);
						if ("senderPrivateKey".equalsIgnoreCase(val))
							sigPrivateKey = senderPrivateKey;
						else if ("receiverPrivateKey".equalsIgnoreCase(val))
							sigPrivateKey = receiverPrivateKey;
						else if ("approverPrivateKey".equalsIgnoreCase(val))
							sigPrivateKey = approverPrivateKey;
					}
					if ("signText".equalsIgnoreCase(cmd.cmdStr))
						signer.signTextFile(input, output, sigPrivateKey, sigPublicCert);
					else if ("signTextStreaming".equalsIgnoreCase(cmd.cmdStr))
						signer.signTextFileStreaming(input, output, sigPrivateKey, sigPublicCert);
					else if ("signBinary".equalsIgnoreCase(cmd.cmdStr))
						signer.signBinaryFile(input, output, sigPrivateKey, sigPublicCert);
					else if ("signBinaryStreaming".equalsIgnoreCase(cmd.cmdStr))
						signer.signBinaryFileStreaming(input, output, senderPrivateKey, senderPublicCert);
					else if ("signXml".equalsIgnoreCase(cmd.cmdStr))
						signer.signXmlFile(input, output, senderPrivateKey, senderPublicCert);
					else if ("signXmlStreaming".equalsIgnoreCase(cmd.cmdStr))
						signer.signXmlFileStreaming(input, output, senderPrivateKey, senderPublicCert);
					else if ("wrapBinaryInXmlAndSign".equalsIgnoreCase(cmd.cmdStr))
						signer.wrapBinaryFileInXmlAndSign(input, output, senderPrivateKey, senderPublicCert);
					else if ("wrapBinaryInXmlAndSignStreaming".equalsIgnoreCase(cmd.cmdStr))
						signer.wrapBinaryFileInXmlAndSignStreaming(input, output, senderPrivateKey, senderPublicCert);
					else if ("wrapTextInXmlAndSign".equalsIgnoreCase(cmd.cmdStr))
						signer.wrapTextFileInXmlAndSign(input, output, senderPrivateKey, senderPublicCert);
					else if ("wrapTextInXmlAndSignStreaming".equalsIgnoreCase(cmd.cmdStr) )
						signer.wrapTextFileInXmlAndSignStreaming(input, output, senderPrivateKey, senderPublicCert);
				} else if ("validateSignature".equalsIgnoreCase(cmd.cmdStr)) {
					sigVerifyCert = null;
					key = "sigVerifyCert".toLowerCase();
					if (cmd.hashCmdArgs.containsKey(key)) {
						val = cmd.hashCmdArgs.get(key);
						if ("senderPublicCert".equalsIgnoreCase(val) || "senderPubCert".equalsIgnoreCase(val))
							sigPublicCert = senderPublicCert;
						else if ("receiverPublicCert".equalsIgnoreCase(val) || "receiverPubCert".equalsIgnoreCase(val))
							sigPublicCert = receiverPublicCert;
						else if ("approverPublicCert".equalsIgnoreCase(val) || "approverPubCert".equalsIgnoreCase(val))
							sigPublicCert = approverPublicCert;
					}
					flag = UtilShared.verifySignatureDOM(input, (sigVerifyCert==null?null:senderPublicCert.getPublicKey()));
					logger.info("signature validation=" + flag);
				}
				else if ("createPkg".equalsIgnoreCase(cmd.cmdStr) || "createPkgWithApprover".equalsIgnoreCase(cmd.cmdStr) ||
						"signAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) || "signAndCreatePkgWithApprover".equalsIgnoreCase(cmd.cmdStr) ||
						"signAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) || "signAndCreatePkgWithApproverStreaming".equalsIgnoreCase(cmd.cmdStr) ||
						"signBinaryAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) || "signTextAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) || 
						"signBinaryAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) || "signTextAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr)) {
					if ("createPkg".equalsIgnoreCase(cmd.cmdStr) && senderGiin != null && receiverGiin != null && receiverPublicCert != null && taxyear != -1)
						output = pkgr.createPkg(input, senderGiin, receiverGiin, receiverPublicCert, taxyear);
					else if ("createPkgWithApprover".equalsIgnoreCase(cmd.cmdStr) && senderGiin != null && receiverGiin != null 
							&& approverGiin != null && receiverPublicCert != null && approverPublicCert != null && taxyear != -1)
						output = pkgr.createPkgWithApprover(input, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approverPublicCert, taxyear);
					else if ("signAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
							senderGiin != null && receiverGiin != null  && receiverPublicCert != null && taxyear != -1)
						output = pkgr.signAndCreatePkg(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, taxyear);
					else if ("signAndCreatePkgWithApprover".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
							senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
						output = pkgr.signAndCreatePkgWithApprover(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, 
								approverGiin, approverPublicCert, taxyear);
					else if ("signAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
							senderGiin != null && receiverGiin != null  && receiverPublicCert != null && taxyear != -1)
						output = pkgr.signAndCreatePkgStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, taxyear);
					else if ("signAndCreatePkgWithApproverStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
							senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
						output = pkgr.signAndCreatePkgWithApproverStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, 
								approverGiin, approverPublicCert, taxyear);
					else if ("signBinaryAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
							senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
						output = pkgr.signBinaryFileAndCreatePkg(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, taxyear, 
								fileFormat);
					else if ("signTextAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
							senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
						output = pkgr.signTextFileAndCreatePkg(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, taxyear);
					else if ("signBinaryAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
							senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
						output = pkgr.signBinaryFileAndCreatePkgStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, taxyear, 
								fileFormat);
					else if ("signTextAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
							senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
						output = pkgr.signTextFileAndCreatePkgStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, taxyear);
				} else if ("unpack".equalsIgnoreCase(cmd.cmdStr) || "unpackForApprover".equalsIgnoreCase(cmd.cmdStr) ) {
					if ("unpack".equalsIgnoreCase(cmd.cmdStr))
						pkgr.unpack(input, receiverPrivateKey);
					if ("unpackForApprover".equalsIgnoreCase(cmd.cmdStr))
						pkgr.unpackForApprover(input, approverPrivateKey);
				} else if ("createBinaryFromSignedBase64Binary".equalsIgnoreCase(cmd.cmdStr)) {
					if (output == null)
						output = input + ".bin";
					UtilShared.createBinaryFileFromSignedBase64BinaryFile(input, output);
				} else if ("createZipPkg".equalsIgnoreCase(cmd.cmdStr)) {
					String[] files = null;
					st = new StringTokenizer(input, "|");
					files = new String[st.countTokens()];
					for (int j = 0; j < files.length; j++)
						files[j] = st.nextToken();
					if (output == null)
						output = senderGiin + "_Payload.zip";
					if (files != null && files.length > 0)
						pkgr.createZipFile(files, output);
					else if (senderGiin != null)
						pkgr.createZipPkg(input, senderGiin, output);
				} else if ("encryptZipPkg".equalsIgnoreCase(cmd.cmdStr) && senderGiin != null && receiverGiin != null  && receiverPublicCert != null && taxyear != -1)
					output = pkgr.encryptZipPkg(input, senderGiin, receiverGiin, receiverPublicCert, null, null, taxyear, fileFormat, binaryEncoding);
				else if ("encryptZipPkgWithApprover".equalsIgnoreCase(cmd.cmdStr) && senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
					output = pkgr.encryptZipPkg(input, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding);
				else if (("unencryptZipPkg".equalsIgnoreCase(cmd.cmdStr) || "decryptZipPkg".equalsIgnoreCase(cmd.cmdStr))&& receiverPrivateKey != null) {
					ArrayList<String> list = pkgr.unencryptZipPkg(input, receiverPrivateKey, false);
					for (int idx = 0; idx < list.size(); idx++) {
						if (list.get(idx).toLowerCase().contains("payload")) {
							output = list.get(idx);
							break;
						}
					}
				}
				else if (("unencryptZipPkgForApprover".equalsIgnoreCase(cmd.cmdStr) || "decryptZipPkgForApprover".equalsIgnoreCase(cmd.cmdStr)) && approverPrivateKey != null) {
					ArrayList<String> list = pkgr.unencryptZipPkg(input, approverPrivateKey, true);
					for (int idx = 0; idx < list.size(); idx++) {
						if (list.get(idx).toLowerCase().contains("payload")) {
							output = list.get(idx);
							break;
						}
					}
				} else if ("extractZipPkg".equalsIgnoreCase(cmd.cmdStr)) {
					pkgr.unzipFile(input);
				}
				logger.info("finished..." + cmd.cmdStr + " input=" + input + (output==null?"":", output=" + output));
			}
			if (pkgr.getSigner().isValidateAllSignature()) {
				logger.info("all signature validation=" + pkgr.getSigner().isValidationSuccess());
			}
		} catch(Exception e) {
			e.printStackTrace();
			throw e;
		}
	}
	
	protected MetadataFileFormat getFileFormat(String ff) {
		if ("PDF".equalsIgnoreCase(ff))
			return MetadataFileFormat.PDF;
		if ("JPG".equalsIgnoreCase(ff))
			return MetadataFileFormat.JPG;
		if ("TXT".equalsIgnoreCase(ff))
			return MetadataFileFormat.TXT;
		if ("RTF".equalsIgnoreCase(ff))
			return MetadataFileFormat.RTF;
		if ("XML".equalsIgnoreCase(ff))
			return MetadataFileFormat.XML;
		return null;
	}
	
	protected MetadataBinaryEncoding getBinaryEncoding(String be) {
		if ("NONE".equalsIgnoreCase(be))
			return MetadataBinaryEncoding.NONE;
		if ("BASE64".equalsIgnoreCase(be) || "BASE_64".equalsIgnoreCase(be))
			return MetadataBinaryEncoding.BASE_64;
		return null;
	}
	
	public static void main(String[] args) throws Exception {
		FATCADataPrepPETestTool m = new FATCADataPrepPETestTool();
		if (args.length > 0)
			m.readConfigAndExceuteCommands(args[0]);
		else
			m.readConfigAndExceuteCommands();
	}
}
