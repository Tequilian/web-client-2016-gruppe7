package com.web;

import java.awt.EventQueue;
import java.awt.Color;
import java.awt.event.*;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import org.apache.commons.codec.binary.Base64;

import javax.swing.JFrame;
import javax.crypto.*; 
import javax.crypto.spec.*; 
import java.security.*;
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
import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.UIManager;


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
	
	private JTextField loginField;
	private JPasswordField passwordField;
	private JLabel lblPassword;
	
	private JTextField regEmail;
	private JPasswordField regPassword;
	private JLabel lblPassword2;


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

		b7 = new JButton("Login");
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

/////////////////////////////////////////////////////////////////////////////////////////////
//1		
		loginField = new JTextField();
		loginField.setFont(UIManager.getFont("FormattedTextField.font"));
		loginField.setBounds(126, 156, 147, 40);
		p1.add(loginField);
		loginField.setColumns(10);
		
		passwordField = new JPasswordField();
		passwordField.setFont(UIManager.getFont("PasswordField.font"));
		passwordField.setBounds(285, 156, 147, 40);
		p1.add(passwordField);
		
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
		//2
		regEmail = new JTextField();
		regEmail.setFont(UIManager.getFont("FormattedTextField.font"));
		regEmail.setBounds(126, 156, 147, 40);
		p2.add(regEmail);
		loginField.setColumns(10);
		
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
		//3
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
							userlist.add(user);
							user_list.add(user.getIdentity());
						}

					}
				} catch (Exception e5) {
					e5.printStackTrace();
				}

			}
		});
		getAll.setFont(new Font("Tahoma", Font.PLAIN, 16));
		getAll.setBounds(121, 23, 97, 25);
		p3.add(getAll);
		
		user_list = new List();
		user_list.setForeground(Color.BLACK);
		user_list.setFont(new Font("Tahoma", Font.BOLD, 16));
		user_list.setBackground(Color.ORANGE);
		user_list.setBounds(26, 54, 192, 347);
		p3.add(user_list);

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

		//-----------------------CLICK LISTENER-----------------------//
		btnRegister.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String email= regEmail.getText();
				char[] password = regPassword.getText().toCharArray();
				SecretKey masterkey = null;
				
				byte[] salt_masterkey = SecureRandom.getSeed(64);
				
	            try {
					SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
					KeySpec keySpec = new PBEKeySpec(password, salt_masterkey, 1000, 256);
					SecretKey tmp = secretKeyFactory.generateSecret(keySpec);
					masterkey = new SecretKeySpec(tmp.getEncoded(), "AES");
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (InvalidKeySpecException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
	            //KeyPair bilden
	            KeyPairGenerator kpg = null;

	            //KeyPairGenerator erzeugen --> Algorithmus: RSA 2048
	            try {
					kpg = KeyPairGenerator.getInstance("RSA");
				} catch (NoSuchAlgorithmException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				}
	            SecureRandom securerandom = new SecureRandom();
	            byte bytes[] = new byte[20];
	            securerandom.nextBytes(bytes);
	            kpg.initialize(2048, securerandom);

	            //KeyPair erzeugen
	            KeyPair kp = kpg.genKeyPair();

	            //publickey und privatekey in Variablen speichern
	            Key pubkey_user = kp.getPublic();
	            Key privkey_user = kp.getPrivate();
	            byte[] privateKeyByte = privkey_user.getEncoded();
	            byte[] publicKeyByte = pubkey_user.getEncoded();
	            String pubKeyStr = new String(Base64.encodeBase64(publicKeyByte,false));

	            // Die Anwendung verschlüsselt privkey_user via AES-ECB-128 mit masterkey zu
	            //  privkey_user_enc.
	            byte[] privkey_user_enc = null;
	            try {
					Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					cipher.init(Cipher.WRAP_MODE,masterkey);
					privkey_user_enc = cipher.wrap(privkey_user);
				} catch (InvalidKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IllegalBlockSizeException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
	            
	            
	            JSONObject regUser = new JSONObject();
	            try {
					regUser.put("identity", email);
					regUser.put("salt_masterkey", salt_masterkey);
					regUser.put("pubkey_user",pubkey_user);
					regUser.put("privkey_user_enc", privkey_user_enc);
				} catch (JSONException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
	         
	            try {
					new Resty().json("http://web2016team7.herokuapp.com/",form(data("identity", email),
							data("salt_masterkey", salt_masterkey.toString()),
							data("pubkey_user",pubkey_user.toString()),
							data("privkey_user_enc", privkey_user_enc.toString())
							));
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
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
