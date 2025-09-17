package com.atrbpn.keycloak.spi.otptncvalidator.helper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;
import java.sql.*;

/**
 * <pre>
 *     helper.com.atrbpn.keycloak.spi.otpvalidator.PostgresDBHelper
 * </pre>
 *
 * @author Muhammad Edwin < edwin at redhat dot com >
 * 19 Apr 2022 20:12
 */
public class PostgresDBHelper {
    private static DataSource ds = null;

    private static final Logger log = LoggerFactory.getLogger(PostgresDBHelper.class);

    static {

        log.info("pulling data from JNDI of KeycloakDS");

        try {
            Context initCxt =  new InitialContext();
            ds = (DataSource) initCxt.lookup("java:jboss/datasources/KeycloakDS");
        } catch (Exception nfe) {
            log.error(nfe.getMessage(), nfe);
            throw new RuntimeException("unable to get JNDI");
        }
    }

    public static Connection getConnection( ) throws SQLException {
        return ds.getConnection();
    }

    public static void closeQuietly(Connection connection) {
        try {
            if(connection != null)
                connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void closeQuietly(ResultSet resultSet) {
        try {
            if(resultSet != null)
                resultSet.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void closeQuietly(PreparedStatement preparedStatement) {
        try {
            if(preparedStatement != null)
                preparedStatement.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
