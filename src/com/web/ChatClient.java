package com.web;

import java.awt.EventQueue;
import java.awt.Color;
import java.awt.event.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.swing.JFrame;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;

import javax.swing.JButton;
import javax.swing.JPanel;

import us.monoid.json.JSONArray;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;
import static us.monoid.web.Resty.*;

import java.awt.CardLayout;
import javax.swing.JLabel;
import java.awt.Font;
import java.awt.List;
import java.awt.SecondaryLoop;

import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.UIManager;
import javax.xml.bind.DatatypeConverter;
import javax.swing.JTextArea;

public class ChatClient implements ActionListener {

	private JFrame frame;

	JButton b1;
	JButton b2;
	JButton b3;
	JButton b4;
	JButton b5;
	JButton b6;
	JButton b7;
	JButton b8;
	JButton b9;

	JFrame f1;
	JFrame f2;
	JFrame f3;
	private List user_list;

	private JTextField loginEmail;
	private JPasswordField loginPassword;
	private JLabel lblPassword;

	private JTextField regEmail;
	private JPasswordField regPassword;
	private JLabel lblPassword2;
	private JTextField chatInput;

	private ChatLogik chatLogik;
	private List MSGList;
	JTextArea chatOutput;

	private String email = "";
	byte[] privkeyByte = null;
	byte[] test = null;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ChatClient window = new ChatClient();
					window.f1.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public ChatClient() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		chatLogik = new ChatLogik();

		f1 = new JFrame("Login");
		f2 = new JFrame("Register");
		f3 = new JFrame("Chat");

		f1.setSize(800, 800);
		f2.setSize(800, 800);
		f3.setSize(800, 800);

		b1 = new JButton("Login");
		b1.setBounds(260, 5, 88, 25);
		b2 = new JButton("Register");
		b2.setBounds(353, 5, 104, 25);
		b3 = new JButton("Chat");
		b3.setBounds(460, 5, 79, 25);

		b4 = new JButton("Login");
		b4.setBounds(260, 5, 88, 25);
		b5 = new JButton("Register");
		b5.setBounds(353, 5, 104, 25);
		b6 = new JButton("Chat");
		b6.setBounds(460, 5, 79, 25);

		b7 = new JButton("Logout");
		b7.setBounds(260, 5, 88, 25);
		b8 = new JButton("Register");
		b8.setBounds(353, 5, 104, 25);
		b9 = new JButton("Chat");
		b9.setBounds(460, 5, 79, 25);

		JPanel p1 = new JPanel();
		JPanel p2 = new JPanel();
		JPanel p3 = new JPanel();

		p1.setBackground(Color.white);
		p2.setBackground(Color.white);
		p3.setBackground(Color.white);

		p1.setLayout(null);
		p2.setLayout(null);
		p3.setLayout(null);

		p1.add(b1);
		p1.add(b2);
		p1.add(b3);

		p2.add(b4);
		p2.add(b5);
		p2.add(b6);

		p3.add(b7);
		p3.add(b8);
		p3.add(b9);

		f1.getContentPane().setLayout(new CardLayout(0, 0));
		f2.getContentPane().setLayout(new CardLayout(0, 0));
		f3.getContentPane().setLayout(new CardLayout(0, 0));

		f1.getContentPane().add(p1, "name_login");
		f2.getContentPane().add(p2, "name_register");
		f3.getContentPane().add(p3, "name_chat");

		// hide Chat Button
		b3.hide();
		b6.hide();

		/////////////////////////////////////////////////////////////////////////////////////////////
		// 1
		loginEmail = new JTextField();
		loginEmail.setFont(UIManager.getFont("FormattedTextField.font"));
		loginEmail.setBounds(126, 156, 147, 40);
		p1.add(loginEmail);
		loginEmail.setColumns(10);

		loginPassword = new JPasswordField();
		loginPassword.setFont(UIManager.getFont("PasswordField.font"));
		loginPassword.setBounds(285, 156, 147, 40);
		p1.add(loginPassword);

		JButton btnLogin = new JButton("Login");
		btnLogin.setBounds(444, 156, 156, 40);
		p1.add(btnLogin);

		JLabel lblUsername = new JLabel("E-Mail");
		lblUsername.setFont(new Font("Tahoma", Font.PLAIN, 18));
		lblUsername.setBounds(126, 125, 147, 30);
		p1.add(lblUsername);

		lblPassword = new JLabel("Password");
		lblPassword.setFont(new Font("Tahoma", Font.PLAIN, 18));
		lblPassword.setBounds(285, 125, 147, 30);
		p1.add(lblPassword);
		/////////////////////////////////////////////////////////////////////////////////////////////
		// 2
		regEmail = new JTextField();
		regEmail.setFont(UIManager.getFont("FormattedTextField.font"));
		regEmail.setBounds(126, 156, 147, 40);
		p2.add(regEmail);
		loginEmail.setColumns(10);

		regPassword = new JPasswordField();
		regPassword.setFont(UIManager.getFont("PasswordField.font"));
		regPassword.setBounds(285, 156, 147, 40);
		p2.add(regPassword);

		JButton btnRegister = new JButton("Register");
		btnRegister.setBounds(444, 156, 156, 40);
		p2.add(btnRegister);

		JLabel lblUsername2 = new JLabel("E-Mail");
		lblUsername2.setFont(new Font("Tahoma", Font.PLAIN, 18));
		lblUsername2.setBounds(126, 125, 147, 30);
		p2.add(lblUsername2);

		lblPassword2 = new JLabel("Password");
		lblPassword2.setFont(new Font("Tahoma", Font.PLAIN, 18));
		lblPassword2.setBounds(285, 125, 147, 30);
		p2.add(lblPassword2);
		/////////////////////////////////////////////////////////////////////////////////////////////
		// 3
		JLabel lblUserlist = new JLabel("Userlist");
		lblUserlist.setFont(new Font("Tahoma", Font.PLAIN, 18));
		lblUserlist.setBounds(26, 25, 112, 16);
		p3.add(lblUserlist);

		JButton getAll = new JButton("Get All");
		getAll.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				user_list.removeAll();
				JSONResource json = null;
				JSONObject status = null;
				JSONArray alluser = null;
				Resty r = new Resty();
				String statusCode = "";
				try {
					try {
						json = r.json("http://web2016team7.herokuapp.com/all");
						status = json.object();
					} catch (ClassCastException e3) {
						alluser = json.array();
					}
					if (status != null) {
						statusCode = status.getString("status_code");
						if (statusCode.equals("461")) {
							user_list.add("Keine User gefunden");
						}
					} else {
						ArrayList<User> userlist = new ArrayList<User>();
						for (int i = 0; i < alluser.length(); i++) {
							User user = new User();
							user.setIdentity(alluser.getJSONObject(i).getString("identity"));
							user.setPubkey_user(alluser.getJSONObject(i).getString("pubkey_user"));
							if (!user.getIdentity().equals(email)) {
								userlist.add(user);
								user_list.add(user.getIdentity());
							}

						}

					}
				} catch (Exception e5) {
					e5.printStackTrace();
				}

			}
		});
		getAll.setFont(new Font("Tahoma", Font.PLAIN, 16));
		getAll.setBounds(26, 52, 97, 25);
		p3.add(getAll);

		user_list = new List();

		user_list.setForeground(Color.BLACK);
		user_list.setFont(new Font("Tahoma", Font.BOLD, 16));
		user_list.setBackground(Color.WHITE);
		user_list.setBounds(26, 85, 97, 347);
		p3.add(user_list);

		chatInput = new JTextField();
		chatInput.setBounds(260, 381, 368, 20);
		p3.add(chatInput);
		chatInput.setColumns(10);

		JButton sendBTN = new JButton("Send");
		sendBTN.setBounds(638, 381, 136, 20);
		p3.add(sendBTN);
		sendBTN.setEnabled(false);
		user_list.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				sendBTN.setEnabled(true);
				setMsgList();
			}
		});

		JButton readBTN = new JButton("Read");
		readBTN.setBounds(685, 25, 89, 23);
		p3.add(readBTN);

		MSGList = new List();
		MSGList.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				chatOutput.setText("");

				// get Nachrichten ID
				int index = MSGList.getSelectedItem().indexOf(".");
				String msgid = MSGList.getSelectedItem().substring(0, index);
				setMsgOutput(msgid);
			}
		});
		MSGList.setForeground(Color.BLACK);
		MSGList.setFont(new Font("Tahoma", Font.BOLD, 16));
		MSGList.setBackground(Color.WHITE);
		MSGList.setBounds(132, 85, 122, 347);
		p3.add(MSGList);

		JLabel lblMsglist = new JLabel("MSGList");
		lblMsglist.setFont(new Font("Tahoma", Font.PLAIN, 18));
		lblMsglist.setBounds(139, 25, 112, 16);
		p3.add(lblMsglist);

		JButton btnNewButton = new JButton("RefreshMSGList");
		btnNewButton.setBounds(133, 52, 103, 26);
		p3.add(btnNewButton);

		chatOutput = new JTextArea();
		chatOutput.setEditable(false);
		chatOutput.setBounds(260, 54, 510, 314);
		p3.add(chatOutput);

		f1.setVisible(true);
		f2.setVisible(false);
		f3.setVisible(false);

		f1.setDefaultCloseOperation(3);
		f2.setDefaultCloseOperation(3);
		f3.setDefaultCloseOperation(3);

		b1.addActionListener(this);
		b2.addActionListener(this);
		b3.addActionListener(this);
		b4.addActionListener(this);
		b5.addActionListener(this);
		b6.addActionListener(this);
		b7.addActionListener(this);
		b8.addActionListener(this);
		b9.addActionListener(this);

		// -----------------------CLICK LISTENER
		// REGISTER-----------------------//
		btnRegister.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String email = regEmail.getText();
				String password = regPassword.getText();
				byte[] salt_masterkey1 = null;
				Key publicKey = null;
				Key privateKey = null;
				byte[] privkey_user_enc = null;
				byte[] masterkey = null;

				// get Salt
				try {
					salt_masterkey1 = getSalt(64);
				} catch (NoSuchAlgorithmException e1) {
					e1.printStackTrace();
				}

				String saltString = null;
				try {
					saltString = new String(salt_masterkey1, "UTF-8");
				} catch (UnsupportedEncodingException e2) {
					e2.printStackTrace();
				}
				byte[] salt_masterkey = null;
				try {
					salt_masterkey = saltString.getBytes("UTF-8");
				} catch (UnsupportedEncodingException e2) {
					e2.printStackTrace();
				}
				// generate masterkey
				try {
					masterkey = deriveKey(password, salt_masterkey, 256);
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				// generate KEYPAIR
				KeyPairGenerator kpg;
				try {
					kpg = KeyPairGenerator.getInstance("RSA");
					kpg.initialize(2048);
					KeyPair kp = kpg.genKeyPair();
					publicKey = kp.getPublic();
					privateKey = kp.getPrivate();
					// test = privateKey.getEncoded();
					// System.out.println(privateKey.getEncoded().toString());
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				// generate privkey_user_enc
				privkey_user_enc = encrypt(masterkey, privateKey);
				System.out.println("1:" + Arrays.toString(publicKey.getEncoded()));
				// System.out.println("RegisterByte "
				// +Arrays.toString(privkey_user_enc));

				BASE64Encoder myEncoder = new BASE64Encoder();
				String geheimPrivKey = myEncoder.encode(privkey_user_enc);
				byte[] pub = publicKey.getEncoded();
				String pubString = null;
				pubString = myEncoder.encode(pub);

				// write to database
				try {
					new Resty().json("http://web2016team7.herokuapp.com/",
							form(data("identity", email), data("salt_masterkey", saltString),
									data("pubkey_user", pubString), data("privkey_user_enc", geheimPrivKey)));
				} catch (Exception e1) {
					e1.printStackTrace();
				}
			}
		});
		// ----------------------ON CLICK LISTENER
		// LOGIN------------------------------------
		btnLogin.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				email = loginEmail.getText();
				String password = loginPassword.getText();
				byte[] masterkey = null;

				Resty r = new Resty();
				JSONObject user = new JSONObject();
				try {
					user = r.json("http://web2016team7.herokuapp.com/" + email).object();
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (JSONException e1) {
					e1.printStackTrace();
				}
				String salt_masterkeyString = null;
				String privkey_user_encString = null;
				String pubkey_userString = null;
				byte[] salt_masterkey = null;
				try {
					salt_masterkeyString = user.getString("salt_masterkey");
					privkey_user_encString = user.getString("privkey_user_enc");
					pubkey_userString = user.getString("pubkey_user");

				} catch (Exception e1) {
					e1.printStackTrace();
				}

				try {
					salt_masterkey = salt_masterkeyString.getBytes("UTF-8");
				} catch (UnsupportedEncodingException e2) {
					e2.printStackTrace();
				}

				// generate masterkey
				try {
					masterkey = deriveKey(password, salt_masterkey, 256);
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				BASE64Decoder myDecoder2 = new BASE64Decoder();
				byte[] crypted2 = null;
				try {
					crypted2 = myDecoder2.decodeBuffer(privkey_user_encString);

				} catch (IOException e1) {
					e1.printStackTrace();
				}
				privkeyByte = decrypt(crypted2, masterkey);
				// System.out.println("2:" +Arrays.toString(privkeyByte));
				// System.out.println("2:" +Arrays.toString(test));
			}
		});
		// ----------------Click Listener SENDEN----------------------
		sendBTN.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				BASE64Encoder myEncoder = new BASE64Encoder();
				BASE64Decoder myDecoder2 = new BASE64Decoder();

				String receiver = "";
				String pubkey_recipient = "";
				String inputText = "";
				byte[] key_receipient = null;
				byte[] iv = null;
				String ivString = "";
				String cipherString = null;
				IvParameterSpec ivspec = null;

				// get recivier identity
				receiver = user_list.getSelectedItem();

				// get Pubkey from Reciver
				Resty r = new Resty();
				JSONObject pubkeyRec = new JSONObject();
				try {
					pubkeyRec = r.json("http://web2016team7.herokuapp.com/" + receiver + "/pubkey").object();
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (JSONException e1) {
					e1.printStackTrace();
				}
				try {
					pubkey_recipient = pubkeyRec.getString("pubkey_user");
				} catch (JSONException e1) {
					e1.printStackTrace();
				}
				// get Nachricht von GUI
				inputText = chatInput.getText();
				// get key_receipient randomly
				try {
					key_receipient = getSalt(16);
				} catch (NoSuchAlgorithmException e1) {
					e1.printStackTrace();
				}
				// get iv randomly
				try {
					iv = getSalt(16);
					ivString = myEncoder.encode(iv);
					ivspec = new IvParameterSpec(iv);
				} catch (NoSuchAlgorithmException e1) {
					e1.printStackTrace();
				}
				// verschlüsselung der Nachricht
				// String inputTextString = myEncoder.encode(inputText);

				byte[] nachricht = encryptMSG(key_receipient, inputText, ivspec);
				String nachrichtString = "";
				nachrichtString = myEncoder.encode(nachricht);

				// get key_receipient_enc mit RSA und pubkey
				byte[] pubkey_recipientByte = null;
				try {
					pubkey_recipientByte = myDecoder2.decodeBuffer(pubkey_recipient);
				} catch (UnsupportedEncodingException e2) {
					e2.printStackTrace();
				} catch (IOException e1) {
					e1.printStackTrace();
				}
				// System.out.println(pubkey_recipient);
				// System.out.println("2:
				// "+Arrays.toString(pubkey_recipientByte));

				//System.out.println("Tes: " + Arrays.toString(key_receipient));

				byte[] key_recipient_enc = encrypt_rec_priv(pubkey_recipientByte, key_receipient);
				String key_recipient_encString = "";
				key_recipient_encString = myEncoder.encode(key_recipient_enc);

				// get PrivKey
				PrivateKey privateKey = null;
				try {
					EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privkeyByte);
					KeyFactory generator = KeyFactory.getInstance("RSA");
					privateKey = generator.generatePrivate(privateKeySpec);
				} catch (NoSuchAlgorithmException e3) {
					e3.printStackTrace();
				} catch (InvalidKeySpecException e1) {
					e1.printStackTrace();
				}

				// get sig_recipient
				byte[] sig_recipient = null;
				String digSignature = email + nachrichtString + ivString + key_recipient_encString;

				Signature sig = null;
				try {
					sig = Signature.getInstance("SHA256withRSA");
					sig.initSign(privateKey);
					sig.update(digSignature.getBytes());
					sig_recipient = sig.sign();
				} catch (InvalidKeyException e2) {
					e2.printStackTrace();
				} catch (NoSuchAlgorithmException e2) {
					e2.printStackTrace();
				} catch (SignatureException e2) {
					e2.printStackTrace();
				}
				String sig_recipientString = myEncoder.encode(sig_recipient);

				// get timestamp
				long unixTime = System.currentTimeMillis() / 1000L;
				String strTime = Long.toString(unixTime);

				// get sig_service
				//System.out.println("3: " + Arrays.toString(privkeyByte));

				byte[] sig_service = null;
				String digSigService = receiver + email + nachrichtString + ivString + key_recipient_encString
						+ strTime;
				String sig_serviceString = "";
				try {
					byte[] data = digSigService.getBytes();

					PublicKey pubKey = null;
					pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubkey_recipientByte));

					Signature sig1 = Signature.getInstance("SHA256withRSA");
					sig1.initSign(privateKey);
					sig1.update(data);
					sig_service = sig1.sign();
					sig_serviceString = myEncoder.encode(sig_service);

				} catch (NoSuchAlgorithmException e1) {
					e1.printStackTrace();
				} catch (SignatureException e1) {
					e1.printStackTrace();
				} catch (InvalidKeyException e1) {
					e1.printStackTrace();
				} catch (InvalidKeySpecException e1) {
					e1.printStackTrace();
				}

				// snede zum Server

				try {
					new Resty().json("http://web2016team7.herokuapp.com/" + receiver + "/msg",
							form(data("sender", email), data("cipher", nachrichtString), data("iv", ivString),
									data("key_recipient_enc", key_recipient_encString), data("timestamp", strTime),
									data("sig_recipient", sig_recipientString),
									data("sig_service", sig_serviceString)));
				} catch (Exception e1) {
					e1.printStackTrace();
				}

				// Nach senden Textbox wieder leer machen
				chatInput.setText("");

			}
		});
		// -------Click Listener RefreshNachrichten--------------------
		readBTN.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				chatOutput.setText("");

				// get Nachrichten ID
				int index = MSGList.getSelectedItem().indexOf(".");
				String msgid = MSGList.getSelectedItem().substring(0, index);
				setMsgOutput(msgid);

			}
		});
		// -----Click getAllMSG---------------------
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				setMsgList();
			}
		});
	}

	public void setMsgOutput(String msgid) {
		String msg = chatLogik.getMsg(msgid, email, privkeyByte);
		chatOutput.append(msg);
	}

	public void setMsgList() {
		MSGList.clear();
		ArrayList<Message> allMsg = chatLogik.getAllMsg(email);

		if (allMsg != null) {
			for (int i = 0; i < allMsg.size(); i++) {
				if (allMsg.get(i).getSender().equals(user_list.getSelectedItem())) {
					if(allMsg.get(i).isRead()){
						MSGList.add(allMsg.get(i).getId() + ". Von " + allMsg.get(i).getSender()+" (Read)");
					}
					else
					{
						MSGList.add(allMsg.get(i).getId() + ". Von " + allMsg.get(i).getSender());
					}
					
				}

			}

		} else {
			MSGList.add("Keine Nachrichten gefunden");
		}
	}

	private byte[] getSalt(int i) throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[i];
		sr.nextBytes(salt);
		return salt;
	}

	public byte[] deriveKey(String password, byte[] salt, int keyLen)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec specs = new PBEKeySpec(password.trim().toCharArray(), salt, 10000, keyLen);
		SecretKey key = kf.generateSecret(specs);
		return key.getEncoded();
	}

	public byte[] encrypt(byte[] masterkey, Key privKey) {
		// System.out.println("ENCMaster: " + Arrays.toString(masterkey));
		try {
			SecretKey masterkey_enc = new SecretKeySpec(masterkey, 0, masterkey.length, "AES");
			byte[] encrypted = null;
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, masterkey_enc);
			return encrypted = cipher.doFinal(privKey.getEncoded());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] encrypt_rec_priv(byte[] pubKeyReceipient, byte[] privKey) {
		// System.out.println(Arrays.toString(privKey.getEncoded()));
		try {
			PublicKey masterKey = KeyFactory.getInstance("RSA")
					.generatePublic(new X509EncodedKeySpec(pubKeyReceipient));
			// SecretKey masterkey_enc = new SecretKeySpec(pubKeyReceipient, 0,
			// pubKeyReceipient.length, "AES");

			byte[] encrypted = null;
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, masterKey);
			return encrypted = cipher.doFinal(privKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] encryptMSG(byte[] key_recipient, String Nachricht, IvParameterSpec iv) {
		byte[] clearText = null;

		SecretKey key_recipient_enc = new SecretKeySpec(key_recipient, 0, key_recipient.length, "AES");
		try {
			Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			encryptCipher.init(Cipher.ENCRYPT_MODE, key_recipient_enc, iv);
			clearText = Nachricht.getBytes("UTF-8");
			return encryptCipher.doFinal(clearText);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | UnsupportedEncodingException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] decrypt(byte[] strToDecrypt, byte[] masterkey) {
		try {
			SecretKey masterkey_enc = new SecretKeySpec(masterkey, 0, masterkey.length, "AES");
			Cipher cipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher2.init(Cipher.DECRYPT_MODE, masterkey_enc);
			b3.setVisible(true);
			return cipher2.doFinal(strToDecrypt);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			b3.setVisible(false);
			e.printStackTrace();
		}

		return null;
	}

	public void actionPerformed(ActionEvent evt) {
		if (evt.getSource() == b1) {
			f1.setVisible(true);
			f2.setVisible(false);
			f3.setVisible(false);
		} else if (evt.getSource() == b2) {
			f1.setVisible(false);
			f2.setVisible(true);
			f3.setVisible(false);
		} else if (evt.getSource() == b3) {
			f1.setVisible(false);
			f2.setVisible(false);
			f3.setVisible(true);
		} else if (evt.getSource() == b4) {
			f1.setVisible(true);
			f2.setVisible(false);
			f3.setVisible(false);
		} else if (evt.getSource() == b5) {
			f1.setVisible(false);
			f2.setVisible(true);
			f3.setVisible(false);
		} else if (evt.getSource() == b6) {
			f1.setVisible(false);
			f2.setVisible(false);
			f3.setVisible(true);
		} else if (evt.getSource() == b7) {
			f1.setVisible(true);
			f2.setVisible(false);
			f3.setVisible(false);
		} else if (evt.getSource() == b8) {
			f1.setVisible(false);
			f2.setVisible(true);
			f3.setVisible(false);
		} else if (evt.getSource() == b9) {
			f1.setVisible(false);
			f2.setVisible(false);
			f3.setVisible(true);
		}

	}
}
