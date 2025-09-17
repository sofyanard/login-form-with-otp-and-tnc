package com.atrbpn.keycloak.spi.otptncvalidator.tnc;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

import javax.naming.Context;
import javax.naming.InitialContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

public class TncRestClient {

    private static final Logger log = LoggerFactory.getLogger(TncRestClient.class);
    
    public static String tncApiBaseUrl;

    static {
        try {
            Context initCxt =  new InitialContext();

            tncApiBaseUrl = (String) initCxt.lookup("java:/tncApiBaseUrl");
            log.info("tncApiBaseUrl: {}", tncApiBaseUrl);

        } catch (Exception ex) {
            tncApiBaseUrl = null;
            log.error("unable to get jndi connection for SMTP or Environment");
            log.error(ex.getMessage(), ex);
        }
    }

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static TncResponse updateUser(TncRequest request) throws IOException {

        // Do REST POST request
        URL url = new URL(tncApiBaseUrl + "/update");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        // Serialize TncRequest to JSON and send
        String jsonRequest = objectMapper.writeValueAsString(request);
        conn.getOutputStream().write(jsonRequest.getBytes("UTF-8"));

        int status = conn.getResponseCode();
        if (status != 200) {
            throw new IOException("REST request failed with status: " + status);
        }

        StringBuilder jsonBuilder = new StringBuilder();
        try (Scanner scanner = new Scanner(conn.getInputStream())) {
            while (scanner.hasNextLine()) {
                jsonBuilder.append(scanner.nextLine());
            }
        }
        conn.disconnect();
        String jsonString = jsonBuilder.toString();

        // Convert JSON response to TncResponse model
        TncResponse response = objectMapper.readValue(jsonString, TncResponse.class);
        return response;
    }

    public Boolean isNeedToUpdate() {
        return tncApiBaseUrl != null && !tncApiBaseUrl.isEmpty();
    }

}
