package com.ionicframework.deploy;

import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.util.regex.Matcher;
import java.net.URL;
import java.net.URI;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

class JsonHttpResponse {
	String message;
	Boolean error;
	JSONObject json;
}

public class IonicDeploy extends CordovaPlugin {
	String server = null;
	Context myContext = null;
	String app_id = null;
	String channel = null;
	String binary_version = null;
	SharedPreferences prefs = null;
	CordovaWebView v = null;
	JSONObject last_update;

	//define callback interface
	interface DownloadCallbackInterface {
		void onDownloadFinished(boolean success);
	}

	/**
	 * Returns the data contained at filePath as a string
	 *
	 * @param filePath the URL of the file to read
	 * @return the string contents of filePath
	 **/
	private static String getStringFromFile(String filePath) throws Exception {
		// Grab the file and init vars
		URI uri = URI.create(filePath);
		File file = new File(uri);
		StringBuilder text = new StringBuilder();
		BufferedReader br = new BufferedReader(new FileReader(file));
		String line;

		//Read text from file
		while ((line = br.readLine()) != null) {
			text.append(line);
			text.append('\n');
		}
		br.close();

		return text.toString();
	}

	private String getStringResourceByName(String aString) {
		Activity activity = cordova.getActivity();
		String packageName = activity.getPackageName();
		int resId = activity.getResources().getIdentifier(aString, "string", packageName);
		return activity.getString(resId);
	}

	/**
	 * Sets the context of the Command. This can then be used to do things like
	 * get file paths associated with the Activity.
	 *
	 * @param cordova  The context of the main Activity.
	 * @param cWebView The CordovaWebView Cordova is running in.
	 */
	public void initialize(CordovaInterface cordova, CordovaWebView cWebView) {
		super.initialize(cordova, cWebView);

		this.myContext = this.cordova.getActivity().getApplicationContext();
		this.prefs = this.myContext.getSharedPreferences("com.ionic.deploy.preferences", Context.MODE_PRIVATE);
		this.v = webView;
		this.app_id = getStringResourceByName("ionic_app_id");
		this.server = getStringResourceByName("ionic_update_api");
		this.channel = getStringResourceByName("ionic_channel_name");

		// detect binary version
		PackageManager packageManager = this.cordova.getActivity().getPackageManager();
		PackageInfo packageInfo;
		try {
			packageInfo = packageManager.getPackageInfo(this.cordova.getActivity().getPackageName(), 0);
			this.binary_version = packageInfo.versionName;
		} catch (PackageManager.NameNotFoundException ex) {
			this.binary_version = "0";
		}

	}

	private String getUUID() {
		return this.prefs.getString("benefits_uuid", "");
	}

	public Object onMessage(String id, Object data) {
		boolean is_nothing = "file:///".equals(String.valueOf(data));
		boolean is_index = "file:///android_asset/www/index.html".equals(String.valueOf(data));
		boolean is_original = is_nothing || is_index;

		if ("onPageStarted".equals(id) && is_original) {
			final String uuid = this.getUUID();

			Log.d("Deploy - onMessage", uuid);

			if (!uuid.equals("")) {
				logMessage("LOAD", "Init Deploy Version");
				this.redirect(uuid);
			}
		}
		return null;
	}

	/**
	 * Executes the request and returns PluginResult.
	 *
	 * @param action          The action to execute.
	 * @param args            JSONArry of arguments for the plugin.
	 * @param callbackContext The callback id used when calling back into JavaScript.
	 * @return True if the action was valid, false if not.
	 */
	public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
		if (action.equals("initialize")) {
			JSONObject conf = new JSONObject(args.getString(0));
			if (conf.has("appId")) {
				this.app_id = conf.getString("appId");
			}
			if (conf.has("host")) {
				this.server = conf.getString("host");
			}
			if (conf.has("channel")) {
				this.channel = conf.getString("channel");
			}

			callbackContext.success();
			return true;
		} else if (action.equals("check")) {
			logMessage("CHECK", "Checking for updates");
			final String channel_tag = this.channel;
			cordova.getThreadPool().execute(new Runnable() {
				public void run() {
					checkForUpdates(callbackContext, channel_tag);
				}
			});
			return true;
		} else if (action.equals("download")) {
			logMessage("DOWNLOAD", "Downloading updates");
			cordova.getThreadPool().execute(new Runnable() {
				public void run() {
					downloadUpdate(callbackContext);
				}
			});
			return true;
		} else if (action.equals("extract")) {
			logMessage("EXTRACT", "Extracting update");
			cordova.getThreadPool().execute(new Runnable() {
				public void run() {
					unzip("www.zip", prefs.getString("benefits_upstream_uuid", ""), callbackContext);
				}
			});
			return true;
		} else if (action.equals("redirect")) {
			this.redirect(this.getUUID());
			callbackContext.success();
			return true;
		} else if (action.equals("info")) {
			this.info(callbackContext);
			return true;
		} else {
			return false;
		}
	}

	private void info(CallbackContext callbackContext) {
		JSONObject json = new JSONObject();

		try {
			json.put("deploy_uuid", this.getUUID());
			json.put("channel", this.channel);
			json.put("binary_version", this.binary_version);
		} catch (JSONException e) {
			callbackContext.error("Unable to gather deploy info: " + e.toString());
		}

		callbackContext.success(json);
	}

	private void checkForUpdates(CallbackContext callbackContext, final String channel_tag) {
		String deployed_version = this.getUUID();
		JsonHttpResponse response = postDeviceDetails(deployed_version, channel_tag);
		this.parseUpdate(callbackContext, response);
	}

	private void parseUpdate(CallbackContext callbackContext, String response) {
		try {
			JsonHttpResponse jsonResponse = new JsonHttpResponse();
			jsonResponse.json = new JSONObject(response);
			parseUpdate(callbackContext, jsonResponse);
		} catch (JSONException e) {
			logMessage("PARSEUPDATE", e.toString());
			callbackContext.error("Error parsing check response.");
		}
	}

	private void parseUpdate(CallbackContext callbackContext, JsonHttpResponse response) {
		this.last_update = null;
		String running_version = this.getUUID();
		String downloaded_version = this.prefs.getString("benefits_upstream_uuid", "");

		try {
			if (response.json != null) {
				JSONObject update = response.json.getJSONObject("data");
				Boolean compatible = Boolean.valueOf(update.getString("compatible"));
				Boolean updatesAvailable = Boolean.valueOf(update.getString("available"));

				if (!compatible) {
					logMessage("PARSEUPDATE", "Refusing update due to incompatible binary version");
				} else if (updatesAvailable) {
					try {
						String update_uuid = update.getString("snapshot");
						if (!update_uuid.equals(running_version) && !update_uuid.equals(downloaded_version)) {
							prefs.edit().putString("benefits_upstream_uuid", update_uuid).apply();
							this.last_update = update;
						} else {
							updatesAvailable = false;
						}

					} catch (JSONException e) {
						callbackContext.error("Update information is not available");
					}
				}

				if (updatesAvailable && compatible) {
					callbackContext.success("true");
				} else {
					callbackContext.success("false");
				}
			} else {
				logMessage("PARSEUPDATE", "Unable to check for updates.");
				callbackContext.success("false");
			}
		} catch (JSONException e) {
			logMessage("PARSEUPDATE", e.toString());
			callbackContext.error("Error checking for updates.");
		}
	}

	private void downloadUpdate(CallbackContext callbackContext) {
		String upstream_uuid = this.prefs.getString("benefits_upstream_uuid", "");
		if (!upstream_uuid.equals("") && !upstream_uuid.equals(this.getUUID())) {
			try {
				String url = this.last_update.getString("url");
				final DownloadTask downloadTask = new DownloadTask(this.myContext, callbackContext);
				downloadTask.execute(url);
			} catch (JSONException e) {
				logMessage("DOWNLOAD", e.toString());
				callbackContext.error("Error fetching download");
			}
		} else {
			callbackContext.success("false");
		}
	}

	/**
	 * Remove a deploy version from the device
	 *
	 * @param uuid
	 * @return boolean Success or failure
	 */
	private boolean removeVersion(String uuid) {
		File versionDir = this.myContext.getDir(uuid, Context.MODE_PRIVATE);
		if (versionDir.exists()) {
			String deleteCmd = "rm -r " + versionDir.getAbsolutePath();
			Runtime runtime = Runtime.getRuntime();
			try {
				runtime.exec(deleteCmd);
				return true;
			} catch (IOException e) {
				logMessage("REMOVE", "Failed to remove " + uuid + ". Error: " + e.getMessage());
			}
		}
		return false;
	}

	private JsonHttpResponse postDeviceDetails(String uuid, final String channel_tag) {
		String endpoint = "/apps/" + this.app_id + "/channels/check-device";
		JsonHttpResponse response = new JsonHttpResponse();
		JSONObject json = new JSONObject();
		JSONObject device_details = new JSONObject();

		try {
			device_details.put("binary_version", this.binary_version); // todo-dave? binary version
			if (!uuid.equals("")) {
				device_details.put("snapshot", uuid);
			}
			device_details.put("platform", "android");
			json.put("channel_name", channel_tag);
			json.put("app_id", this.app_id);
			json.put("device", device_details);

			String params = json.toString();
			byte[] postData = params.getBytes("UTF-8");
			int postDataLength = postData.length;

			URL url = new URL(this.server + endpoint);
			HttpURLConnection.setFollowRedirects(true);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();

			conn.setDoOutput(true);
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Content-Type", "application/json");
			conn.setRequestProperty("Accept", "application/json");
			conn.setRequestProperty("Charset", "utf-8");
			conn.setRequestProperty("Content-Length", Integer.toString(postDataLength));

			DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
			wr.write(postData);

			InputStream in = new BufferedInputStream(conn.getInputStream());
			String result = readStream(in);

			JSONObject jsonResponse = new JSONObject(result);
			logMessage("POST_CHECK_RES", jsonResponse.toString(2));

			response.json = jsonResponse;
		} catch (JSONException e) {
			logMessage("POST_CHECK_ERR", e.getMessage());
			response.error = true;
		} catch (MalformedURLException e) {
			logMessage("POST_CHECK_ERR", e.getMessage());
			response.error = true;
		} catch (IOException e) {
			logMessage("POST_CHECK_ERR", e.getMessage());
			response.error = true;
		}

		return response;
	}

	private String readStream(InputStream is) {
		try {
			ByteArrayOutputStream bo = new ByteArrayOutputStream();
			int i = is.read();
			while (i != -1) {
				bo.write(i);
				i = is.read();
			}
			return bo.toString();
		} catch (IOException e) {
			return "";
		}
	}

	private void logMessage(String tag, String message) {
		Log.i("IONIC.DEPLOY." + tag, message);
	}

	/**
	 * Extract the downloaded archive
	 *
	 * @param zip
	 * @param upstream_uuid
	 */
	private void unzip(String zip, String upstream_uuid, CallbackContext callbackContext) {
		logMessage("UNZIP", upstream_uuid);

		if (upstream_uuid.equals("") || upstream_uuid.equals(this.getUUID())) {
			callbackContext.success("false"); // we have already extracted this version
			return;
		}

		try {
			FileInputStream inputStream = this.myContext.openFileInput(zip);
			ZipInputStream zipInputStream = new ZipInputStream(inputStream);
			ZipEntry zipEntry = null;

			// Make the version directory in internal storage
			File versionDir = this.myContext.getDir(upstream_uuid, Context.MODE_PRIVATE);

			logMessage("UNZIP_DIR", versionDir.getAbsolutePath());

			// Figure out how many entries are in the zip so we can calculate extraction progress
			ZipFile zipFile = new ZipFile(this.myContext.getFileStreamPath(zip).getAbsolutePath());
			float entries = zipFile.size();

			logMessage("ENTRIES", "Total: " + (int) entries);

			float extracted = 0.0f;

			while ((zipEntry = zipInputStream.getNextEntry()) != null) {
				if (zipEntry.getSize() != 0) {
					File newFile = new File(versionDir + "/" + zipEntry.getName());
					newFile.getParentFile().mkdirs();

					byte[] buffer = new byte[2048];

					FileOutputStream fileOutputStream = new FileOutputStream(newFile);
					BufferedOutputStream outputBuffer = new BufferedOutputStream(fileOutputStream, buffer.length);
					int bits;
					while ((bits = zipInputStream.read(buffer, 0, buffer.length)) != -1) {
						outputBuffer.write(buffer, 0, bits);
					}

					zipInputStream.closeEntry();
					outputBuffer.flush();
					outputBuffer.close();

					extracted += 1;

					float progress = (extracted / entries) * Float.valueOf("100.0f");
					logMessage("EXTRACT", "Progress: " + (int) progress + "%");

					PluginResult progressResult = new PluginResult(PluginResult.Status.OK, (int) progress);
					progressResult.setKeepCallback(true);
					callbackContext.sendPluginResult(progressResult);
				}
			}
			zipInputStream.close();

		} catch (Exception e) {
			//TODO Handle problems..
			logMessage("UNZIP_STEP", "Exception: " + e.getMessage());

			// clean up any zip files dowloaded as they may be corrupted, we can download again if we start over
			String wwwFile = this.myContext.getFileStreamPath(zip).getAbsolutePath();
			if (this.myContext.getFileStreamPath(zip).exists()) {
				String deleteCmd = "rm -r " + wwwFile;
				Runtime runtime = Runtime.getRuntime();
				try {
					runtime.exec(deleteCmd);
					logMessage("REMOVE", "Removed www.zip");
				} catch (IOException ioe) {
					logMessage("REMOVE", "Failed to remove " + wwwFile + ". Error: " + e.getMessage());
				}
			}

			callbackContext.error(e.getMessage());
			return;
		}

		// delete the downloaded "www.zip"
		String wwwFile = this.myContext.getFileStreamPath(zip).getAbsolutePath();
		if (this.myContext.getFileStreamPath(zip).exists()) {
			String deleteCmd = "rm -r " + wwwFile;
			Runtime runtime = Runtime.getRuntime();
			try {
				runtime.exec(deleteCmd);
				logMessage("REMOVE", "Removed www.zip");
			} catch (IOException e) {
				logMessage("REMOVE", "Failed to remove " + wwwFile + ". Error: " + e.getMessage());
				callbackContext.error(e.getMessage());
				return;
			}
		}

		// modify the new "index.html" file
		final File versionDir = this.myContext.getDir(upstream_uuid, Context.MODE_PRIVATE);
		try {
			// Parse new index as a string and update the cordova.js reference
			File newIndexFile = new File(versionDir, "index.html");
			String newIndex = IonicDeploy.updateIndexCordovaReference(getStringFromFile(newIndexFile.toURI().toString()));

			// Save the new index.html
			FileWriter fw = new FileWriter(newIndexFile);
			fw.write(newIndex);
			fw.close();
		} catch (Exception e) {
			logMessage("MODIFY INDEX.HTML", "Pre-redirect cordova injection exception: " + Log.getStackTraceString(e));
			callbackContext.error(e.getMessage());
			return;
		}

		// store new version and remove old one
		final String prev_uuid = this.getUUID();
		this.prefs.edit().putString("benefits_uuid", upstream_uuid).apply();
		this.prefs.edit().remove("benefits_upstream_uuid").apply();
		if (!prev_uuid.equals("")) {
			this.removeVersion(prev_uuid);
		}

		callbackContext.success("true");
	}

	/**
	 * Updates the new index.html, the active UUID, and redirects the webview to a given UUID's deploy.
	 *
	 * @param uuid the UUID of the deploy to redirect to
	 **/
	private void redirect(final String uuid) {
		if (!uuid.equals("")) {
			// Load in the new index.html
			cordova.getActivity().runOnUiThread(new Runnable() {
				@Override
				public void run() {
					logMessage("REDIRECT", "Loading deploy version: " + uuid);
					try {
						final String indexLocation = new File(myContext.getDir(uuid, Context.MODE_PRIVATE), "index.html").toURI().toString();
						webView.loadUrlIntoView(indexLocation, false);
						webView.clearHistory();
					} catch (Exception e) {
						logMessage("REDIRECT", "Pre-redirect cordova injection exception: " + Log.getStackTraceString(e));
					}
				}
			});
		}
	}

	/**
	 * Takes an index.html file parsed as a string and updates any extant references to cordova.js contained within to be
	 * valid for deploy.
	 *
	 * @param indexStr the string contents of index.html
	 * @return the updated string index.html
	 **/
	private static String updateIndexCordovaReference(String indexStr) {
		// Init the new script
		String newReference = "<script src=\"file:///android_asset/www/cordova.js\"></script>";

		// Define regular expressions
		String commentedRegexString = "<!--.*<script src=(\"|')(.*\\/|)cordova\\.js.*(\"|')>.*<\\/script>.*-->";  // Find commented cordova.js
		String cordovaRegexString = "<script src=(\"|')(.*\\/|)cordova\\.js.*(\"|')>.*<\\/script>";  // Find cordova.js
		String scriptRegexString = "<script.*>.*</script>";  // Find a script tag

		// Compile the regexes
		Pattern commentedRegex = Pattern.compile(commentedRegexString);
		Pattern cordovaRegex = Pattern.compile(cordovaRegexString);
		Pattern scriptRegex = Pattern.compile(scriptRegexString);

		// First, make sure cordova.js isn't commented out.
		if (commentedRegex.matcher(indexStr).find()) {
			// It is, let's uncomment it.
			indexStr = indexStr.replaceAll(commentedRegexString, newReference);
		} else {
			// It's either uncommented or missing
			// First let's see if it's uncommented
			if (cordovaRegex.matcher(indexStr).find()) {
				// We found an extant cordova.js, update it
				indexStr = indexStr.replaceAll(cordovaRegexString, newReference);
			} else {
				// No cordova.js, gotta inject it!
				// First, find the first script tag we can
				Matcher scriptMatcher = scriptRegex.matcher(indexStr);
				if (scriptMatcher.find()) {
					// Got the script, add cordova.js below it
					String newScriptTag = String.format("%s\n%s\n", scriptMatcher.group(0), newReference);
				}
			}
		}

		return indexStr;
	}

	private class DownloadTask extends AsyncTask<String, Integer, String> {
		private Context myContext;
		private CallbackContext callbackContext;
		private IonicDeploy deploy;

		public DownloadTask(Context context, CallbackContext callbackContext) {
			this.myContext = context;
			this.callbackContext = callbackContext;
			this.deploy = null;
		}

		public DownloadTask(Context context, IonicDeploy deploy) {
			this.myContext = context;
			this.callbackContext = null;
			this.deploy = deploy;
		}

		@Override
		protected String doInBackground(String... sUrl) {
			InputStream input = null;
			FileOutputStream output = null;
			HttpURLConnection connection = null;
			try {
				URL url = new URL(sUrl[0]);
				HttpURLConnection.setFollowRedirects(true);
				connection = (HttpURLConnection) url.openConnection();
				connection.connect();

				// expect HTTP 200 OK, so we don't mistakenly save error report
				// instead of the file
				if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
					String msg = "Server returned HTTP " + connection.getResponseCode() + " " + connection.getResponseMessage();
					if (this.callbackContext != null) {
						this.callbackContext.error(msg);
					}
					return msg;
				}

				// this will be useful to display download percentage
				// might be -1: server did not report the length
				float fileLength = connection.getContentLength();

				logMessage("DOWNLOAD", "File size: " + fileLength);

				// download the file
				input = connection.getInputStream();
				output = this.myContext.openFileOutput("www.zip", Context.MODE_PRIVATE);

				byte data[] = new byte[4096];
				float total = 0;
				int count;
				while ((count = input.read(data)) != -1) {
					total += count;

					output.write(data, 0, count);

					// Send the current download progress to a callback
					if (fileLength > 0) {
						float progress = (total / fileLength) * Float.valueOf("100.0f");
						logMessage("DOWNLOAD", "Progress: " + (int) progress + "%");
						if (this.callbackContext != null) {
							PluginResult progressResult = new PluginResult(PluginResult.Status.OK, (int) progress);
							progressResult.setKeepCallback(true);
							this.callbackContext.sendPluginResult(progressResult);
						}
					}
				}
			} catch (Exception e) {
				if (this.callbackContext != null) {
					this.callbackContext.error("Something failed with the download...");
				}
				return e.toString();
			} finally {
				try {
					if (output != null)
						output.close();
					if (input != null)
						input.close();
				} catch (IOException ignored) {

				}

				if (connection != null)
					connection.disconnect();
			}

			this.callbackContext.success("true");
			return null;
		}
	}
}
