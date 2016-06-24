package com.web;

import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.custom.ScrolledComposite;

import java.util.ArrayList;

import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Text;

import us.monoid.json.JSONArray;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;

import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.List;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;

public class Chat {

	protected Shell shlChatclient;
	private Label label;
	private Text enter_textfield;
	private Label lblEnterYourText;
	private Button send_button;
	private List user_list;
	private Button getUser;

	/**
	 * Launch the application.
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			Chat window = new Chat();
			window.open();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Open the window.
	 */
	public void open() {
		Display display = Display.getDefault();
		createContents();
		shlChatclient.open();
		shlChatclient.layout();
		while (!shlChatclient.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
	}

	/**
	 * Create contents of the window.
	 */
	protected void createContents() {
		shlChatclient = new Shell();
		shlChatclient.setSize(501, 471);
		shlChatclient.setText("ChatClient");
		shlChatclient.setLayout(null);

		label = new Label(shlChatclient, SWT.NONE);
		label.setBounds(5, 10, 56, 20);
		label.setText("Userlist");

		getUser = new Button(shlChatclient, SWT.NONE);
		getUser.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
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

		getUser.setBounds(67, 5, 55, 30);
		getUser.setText("Get all");

		user_list = new List(shlChatclient, SWT.BORDER | SWT.H_SCROLL);
		user_list.setBounds(5, 40, 117, 224);

		lblEnterYourText = new Label(shlChatclient, SWT.NONE);
		lblEnterYourText.setBounds(5, 304, 96, 20);
		lblEnterYourText.setText("Enter your text");

		enter_textfield = new Text(shlChatclient, SWT.BORDER);
		enter_textfield.setBounds(126, 268, 292, 90);

		send_button = new Button(shlChatclient, SWT.NONE);
		send_button.setBounds(126, 364, 45, 30);
		send_button.setText("Send");

		List chat_list = new List(shlChatclient, SWT.BORDER);
		chat_list.setBounds(128, 40, 345, 224);

	}
}
