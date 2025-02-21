<?php

/******************************************************************************
 * This file contains the server side PHP code that students need to modify 
 * to implement the password safe application.  Another PHP file, server.php,
 * should not need to be modified and handles initialization of some variables,
 * resource arbitration, and outputs the reponse.  The last PHP file is api.php
 * which should also not be modified by students and which provides an API
 * for resource functions to communicate with clients.
 * 
 * Student code in this file should only interact with the outside world via
 * the parameters to the functions.  These parameters are the same for each 
 * function.  The Request and Reponse classes can be found in api.php.
 * For more information on PDO database connections, see the documentation at
 * https://www.php.net/manual/en/book.pdo.php or other websites.
 *
 * The parameters to each function are:
 *   -- $request A Request object, passed by reference (see api.php)
 *   -- $response A Response object, passed by reference (see api.php)
 *   -- $db A PDO database connection, passed by reference
 *
 * The functions must also return the same values.  They are:
 *   -- true on success, false on failure
 *
 * Students should understand how to use the Request and Response objects, so
 * please spend some time looking at the code in api.php.  Apart from those
 * classes, the only other API function that students should use is the
 * log_to_console function, which MUST be used for server-side logging.
 *
 * The functions that need to be implemented all handle a specific type of
 * request from the client.  These map to the resources the client JavaScript
 * will call when the user performs certain actions.
 * The functions are:
 *    - preflight -- This is a special function in that it is called both 
 *                   as a separate "preflight" resource and it is also called
 *                   before every other resource to perform any preflight 
 *                   checks and insert any preflight response.  It is 
 *                   especially important that preflight returns true if the
 *                   request succeeds and false if something is wrong.
 *                   See server.php to see how preflight is called.
 *    - signup -- This resource should create a new account for the user
 *                if there are no problems with the request.
 *    - identify -- This resource identifies a user and returns any 
 *                  information that the client would need to log in.  You 
 *                  should be especially careful not to leak any information 
 *                  through this resource.
 *    - login -- This resource checks user credentials and, if they are valid,
 *               creates a new session.
 *    - sites -- This resource should return a list of sites that are saved
 *               for a logged in user.  This result is used to populate the 
 *               dropdown select elements in the user interface.
 *    - save -- This resource saves a new (or replaces an existing) entry in 
 *              the password safe for a logged in user.
 *    - load -- This resource loads an existing entry from the password safe
 *              for a logged in user.
 *    - logout -- This resource should destroy the existing user session.
 *
 * It is VERY important that resources set appropriate HTTP response codes!
 * If a resource returns a 5xx code (which is the default and also what PHP 
 * will set if there is an error executing the script) then I will assume  
 * there is a bug in the program during grading.  Similarly, if a resource
 * returns a 2xx code when it should fail, or a 4xx code when it should 
 * succeed, then I will assume it has done the wrong thing.
 *
 * You should not worry about the database getting full of old entries, so
 * don't feel the need to delete expired or invalid entries at any point.
 *
 * The database connection is to the sqlite3 database "passwordsafe.db".
 * The commands to create this database (and therefore its schema) can
 * be found in "initdb.sql".  You should familiarize yourself with this
 * schema.  Not every table or field must be used, but there are many 
 * helpful hints contained therein.
 * The database can be accessed to run queries on it with the command:
 *    sqlite3 passwordsafe.db
 * It is also easy to run SQL scripts on it by sending them to STDIN.
 *    sqlite3 passwordsafe.db < myscript.sql
 * This database can be recreated (to clean it up) by running:
 *    sqlite3 passwordsafe.db < dropdb.sql
 *    sqlite3 passwordsafe.db < initdb.sql
 *
 * This is outlined in more detail in api.php, but the Response object
 * has a few methods you will need to use:
 *    - set_http_code -- sets the HTTP response code (an integer)
 *    - success       -- sets a success status message
 *    - failure       -- sets a failure status message
 *    - set_data      -- returns arbitrary data to the client (in json)
 *    - set_cookie    -- sets an HTTP-only cookie on the client that
 *                       will automatically be returned with every 
 *                       subsequent request.
 *    - delete_cookie -- tells the client to delete a cookie.
 *    - set_token     -- passes a token (via data, not headers) to the
 *                       client that will automatically be returned with 
 *                       every subsequent request.
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * To get the current date and time in a format the database expects:
 *      $now = new DateTime();
 *      $now->format(DateTimeInterface::ISO8601);
 *
 * To get a date and time 15 minutes in the future (for the database):
 *      $now = new DateTime();
 *      $interval = new DateInterval("PT15M");
 *      $now->add($interval)->format(DateTimeInterface::ISO8601);
 *
 * Notice that, like JavaScript, PHP is loosely typed.  A common paradigm in
 * PHP is for a function to return some data on success or false on failure.
 * Care should be taken with these functions to test for failure using === 
 * (as in, if($result !== false ) {...}) because not using === or !== may 
 * result in unexpected ceorcion of a valid response (0) to false.
 * 
 *****************************************************************************/


/**
 * Performs any resource agnostic preflight validation and can set generic response values.
 * If the request fails any checks, preflight should return false and set appropriate
 * HTTP response codes and a failure message.  Returning false will prevent the requested
 * resource from being called.
 */
function preflight(&$request, &$response, &$db) {
  $response->set_http_code(200);
  $response->success("Request OK");
  log_to_console("OK");

  return true;
}

/**
 * Tries to sign up the username with the email and password.
 * The username and email must be unique and valid, and the password must be valid.
 * Note that it is fine to rely on database constraints.
 */
function signup(&$request, &$response, &$db) {
  $username = $request->param("username"); // The requested username from the client
  $password = $request->param("password"); // The requested password from the client
  $email    = $request->param("email");    // The requested email address from the client
  
  // the db contraints will ensure that the username and email are unique

  $now = new DateTime('NOW');
  $time = $now->format(DateTime::ATOM);

  $salt_bytes = random_bytes(16);
  $salt_hexstr = bin2hex($salt_bytes);
  // concatenate
  $pw_salt = (hex2bin($password)).$salt_bytes;
  $hash_pw_salt_hexstr = hash("sha256", $pw_salt, false);
  // store the salt for this user
  $sql = "INSERT INTO user_login (username, salt, challenge, expires) VALUES ('$username', '$salt_hexstr', 0, '$time')";
  try {
    $sth = $db->prepare($sql);
    $sth->execute();
    log_to_console("Records added successfully.");
  } catch (Exception $ex) {
    log_to_console($ex->getmessage());
    goto fail;
  }

  // store hash of password || salt
  $sql = "INSERT INTO user (username, passwd, email, valid, modified) VALUES ('$username', '$hash_pw_salt_hexstr', '$email', 1, '$time')";
  log_to_console("Executing: $sql.");
  try {
    $sth = $db->prepare($sql);
    $sth->execute();
    log_to_console("Query Success: $sql");
  } catch (Exception $ex) {
    log_to_console($ex->getmessage());
    goto fail;
  }

  // Respond with a message of success.
  $response->set_http_code(201); // Created
  $response->success("Account created.");
  log_to_console("Account created.");

  return true;

fail:
  $response->set_http_code(401);
  $response->failure("Could not create account.");
  log_to_console("Could not create account.");
  return false;
}


/**
 * Handles identification requests.
 * This resource should return any information the client will need to produce 
 * a log in attempt for the given user.
 * Care should be taken not to leak information!
 */
function identify(&$request, &$response, &$db) {
  $username = $request->param("username"); // The username

  // Generate random challenge
  $challenge_bytes = random_bytes(16);
  $challenge_hexstr = bin2hex($challenge_bytes);
  $salt_hexstr = "";
  // Query user_login table for user's salt
  try {
    $sql = "SELECT salt from user_login WHERE username='$username'";
    $sth = $db->prepare($sql);
    $sth->execute();
    $result = $sth->fetch();
    if (!is_array($result)) {
      log_to_console("Could not find user: $username");
      goto fail;
    }
    $salt_hexstr = $result["salt"];
    log_to_console("Query Success: $sql");
  } catch (Exception $ex) {
    log_to_console($ex->getmessage());
    goto fail;
  }

  // Update the user_login table
  $now = new DateTime('NOW');
  $interval = new DateInterval("PT15M");
  $expire = $now->add($interval)->format(DateTime::ATOM);
  try {
    $sql = "UPDATE user_login SET challenge='$challenge_hexstr', expires='$expire' WHERE username='$username'";
    $sth = $db->prepare($sql);
    $sth->execute();
    log_to_console("Query Success: $sql");
  } catch (Exception $ex) {
    log_to_console($ex->getmessage());
    goto fail;
  }

  // Transmit salt and challenge
  $response->set_http_code(200);
  $response->success("Successfully identified user.");
  $response->set_data("challenge", $challenge_hexstr);
  $response->set_data("salt", $salt_hexstr);
  log_to_console("Successfully identified user, sending challenge and salt.");
  log_to_console("Challenge $challenge_hexstr");
  log_to_console("Salt $salt_hexstr");
  return true;

fail:
  $response->set_http_code(404);
  $response->failure("Could not identify user.");
  return false;
}

/**
 * Handles login attempts.
 * On success, creates a new session.
 * On failure, fails to create a new session and responds appropriately.
 */
function login(&$request, &$response, &$db) {
  $username = $request->param("username"); // The username with which to log in
  $password = $request->param("password"); // The password with which to log in

  // Query user_login table for salt
  try {
    $sql = "SELECT challenge, salt FROM user_login WHERE username='$username'";
    $sth = $db->prepare($sql);
    $sth->execute();
    $result = $sth->fetch();
    $salt_hexstr = $result["salt"];
    $challenge_hexstr = $result["challenge"];
    log_to_console("Query Success: $sql");
  } catch (Exception $ex) {
    log_to_console($ex->getmessage());
    return false;
  }

  // Query user for h(password || salt)
  try {
    $sql = "SELECT passwd FROM user WHERE username='$username'";
    $sth = $db->prepare($sql);
    $sth->execute();
    $result = $sth->fetch();
    $hash_pw_salt_hexstr = $result["passwd"];
    log_to_console("Query Success: $sql");
  } catch (Exception $ex) {
    log_to_console($ex->getmessage());
    return false;
  } 

  // compute h(h(password || salt) || challenge)
  $answer_hexstr = hash("sha256", hex2bin($hash_pw_salt_hexstr.$challenge_hexstr), false);

  // Compare to user's resp
  log_to_console("Server computed: $answer_hexstr");
  log_to_console("Received: $password");
  if ($answer_hexstr == $password) {
    log_to_console("Valid challenge response");
    $response->set_http_code(200); // OK
    $response->success("Successfully logged in.");
    // determine sessionid
    try {
      $sql = "SELECT sessionid FROM user_session WHERE username='$username'";
      $sth = $db->prepare($sql);
      $sth->execute();
      $result = $sth->fetch();
      $sessionid =  bin2hex(random_bytes(8));
      $now = new DateTime('NOW');
      $interval = new DateInterval("PT10M");
      $expires = $now->add($interval)->format(DateTime::ATOM);
      if (!is_array($result)) { // No sessionid for this user
        $sql = "INSERT INTO user_session (sessionid, username, expires) VALUES ('$sessionid', '$username', '$expires')";
        $sth = $db->prepare($sql);
        $sth->execute();
        log_to_console("Query Success: $sql");
      } else { // sessionid exists for this user..? so refresh or what?
        $sql = "UPDATE user_session SET sessionid='$sessionid', expires='$expires' WHERE username='$username'";
        $sth = $db->prepare($sql);
        $sth->execute();
        log_to_console("Query Success: $sql");
      }
    } catch (Exception $ex) {
      log_to_console($ex->getmessage());
      goto fail;
    }
    
    session_start();
    session_id($sessionid);

    // $_SESSION["favcolor"] = "green";
    $response->set_cookie("sessionid", $sessionid);
    log_to_console("Session created: $sessionid");
    return true;
  } else {
    log_to_console("Invalid challenge response");
  }

fail:
  $response->set_http_code(401); // Unauthorized
  $response->failure("Invalid password.");
  return false;

}


/**
 * Returns the sites for which a password is already stored.
 * If the session is valid, it should return the data.
 * If the session is invalid, it should return 401 unauthorized.
 */
function sites(&$request, &$response, &$db) {
  $sites = array();

  // apparently the request is empty
  $sessionid = $request->cookie("sessionid");
  log_to_console("Retrieved sessionid from cookie: $sessionid");
  try {
    $sql = "SELECT username, expires FROM user_session WHERE sessionid='$sessionid'";
    $sth = $db->prepare($sql);
    $sth->execute();
    $result = $sth->fetch();
    log_to_console("Query Success: $sql");
    if (!is_array($result)) {
      goto fail;
    }
    $username = $result["username"];
    $expires = $result["expires"];
    $now = new DateTime('NOW');
    $now = $now->format(DateTime::ATOM);
    if ($expires < $now) {
      log_to_console($expires);
      log_to_console($now);
      log_to_console("Session expired");
      goto fail;
    }

    // Query sites saved by this user
    $sql = "SELECT site FROM user_safe WHERE username='$username'";
    $sth = $db->prepare($sql);
    $sth->execute();
    $results = $sth->fetchAll(PDO::FETCH_COLUMN, 0);
    log_to_console("Query Success: $sql");
    if (!is_array($result)) {
      log_to_console("No sites saved by this user");
    }

  } catch (Exception $ex) {
    log_to_console($ex->getmessage());
    goto fail;
  }

  $response->set_data("sites", $results); // return the sites array to the client
  $response->set_http_code(200);
  $response->success("Sites with recorded passwords.");
  log_to_console("Found and returned sites.");

  return true;
fail:
  $response->set_http_code(401);
  $response->failure("Session is invalid.");
  return false;
}

/**
 * Saves site and password data when passed from the client.
 * If the session is valid, it should save the data, overwriting the site if it exists.
 * If the session is invalid, it should return 401 unauthorized.
 */
function save(&$request, &$response, &$db) {
  $site       = $request->param("site");
  $siteuser   = $request->param("siteuser");
  $sitepasswd = $request->param("sitepasswd");
  $siteiv     = $request->param("iv");

  // query user_session for
  $sessionid = $request->cookie("sessionid");
  try {
    $sql = "SELECT username, expires FROM user_session WHERE sessionid='$sessionid'";
    $sth = $db->prepare($sql);
    $sth->execute();
    $result = $sth->fetch();
    if (!is_array($result)) {
      log_to_console("Empty query");
      goto fail;
    }
    log_to_console("Query Success: $sql");
    $username = $result["username"];
    $expires = $result["expires"];
    $now = new DateTime('NOW');
    $now = $now->format(DateTime::ATOM);
    if ($expires < $now) {
      log_to_console("Session expired");
      goto fail;
    }
  }  catch (Exception $ex) {
    log_to_console($ex->getmessage());
    goto fail;
  }

  $now = new DateTime('NOW');
  $modified = $now->format(DateTime::ATOM);
  // Check if an entry of user, site already exists in user_safe
  try {
    $sql = "SELECT * from user_safe WHERE username='$username' AND site='$site'";
    $sth = $db->prepare($sql);
    $sth->execute();
    $result = $sth->fetch();
  }  catch (Exception $ex) {
    log_to_console($ex->getmessage());
    goto fail;
  }
  if (is_array($result)) {
    try {
      $sql = "UPDATE user_safe SET siteuser='$siteuser', sitepasswd='$sitepasswd', siteiv='$siteiv', modified='$modified' WHERE username='$username' AND site='$site'";
      $sth = $db->prepare($sql);
      $sth->execute();
      log_to_console("Query Success: $sql");
    } catch (Exception $ex) {
      log_to_console($ex->getmessage());
      goto fail;
    }
  } else {
    try {
      $sql = "INSERT INTO user_safe (username, site, siteuser, sitepasswd, siteiv, modified) VALUES ('$username', '$site', '$siteuser', '$sitepasswd', '$siteiv', '$modified')";
      $sth = $db->prepare($sql);
      $sth->execute();
      log_to_console("Query Success: $sql");
    } catch (Exception $ex) {
      log_to_console($ex->getmessage());
      goto fail;
    }
  }

  $response->set_http_code(200); // OK
  $response->success("Save to safe succeeded.");
  log_to_console("Successfully saved site data");
  return true;

fail:
  $response->set_http_code(401);
  $response->failure("Save to safe failed.");
  log_to_console("Save to safe failed");
  return false;
}

/**
 * Gets the data for a specific site and returns it.
 * If the session is valid and the site exists, return the data.
 * If the session is invalid return 401, if the site doesn't exist return 404.
 */
function load(&$request, &$response, &$db) {
  $site = $request->param("site");
  $username = $request->param("username");

  // Check the session
  $sessionid = $request->cookie("sessionid");
  try {
    $sql = "SELECT expires FROM user_session WHERE sessionid='$sessionid'";
    $sth = $db->prepare($sql);
    $sth->execute();
    $result = $sth->fetch();
    if (!is_array($result)) {
      log_to_console("No sessionid");
      goto bad_session;
    }
    log_to_console("Query Success: $sql");
    $expires = $result["expires"];
    $now = new DateTime('NOW');
    $now = $now->format(DateTime::ATOM);
    if ($expires < $now) {
      log_to_console($expires);
      log_to_console($now);
      log_to_console("Session expired");
      goto bad_session;
    }
  }  catch (Exception $ex) {
    log_to_console($ex->getmessage());
    goto bad_session;
  }

  try {
    $sql = "SELECT siteuser, sitepasswd, siteiv FROM user_safe WHERE username='$username' AND site='$site'";
    $sth = $db->prepare($sql);
    $sth->execute();
    $result = $sth->fetch();
    log_to_console("$sql");
    if (!is_array($result)) {
      log_to_console("Could not find sitepasswd for $username, $site");
      goto no_site;
    }
    $sitepasswd = $result["sitepasswd"];
    $siteuser = $result["siteuser"];
    $siteiv = $result["siteiv"];
  } catch (Exception $ex) {
    log_to_console($ex->getmessage());
    goto no_site;
  }
  
  $response->set_data("site", $site);
  $response->set_data("siteuser", $siteuser);
  $response->set_data("sitepasswd", $sitepasswd);
  $response->set_data("siteiv", $siteiv);
  $response->set_http_code(200); // OK
  $response->success("Site data retrieved.");
  log_to_console("Site data retrieved.");
  return true;

bad_session:
  $response->set_http_code(401);
  $response->success("Session Invalid.");
  log_to_console("Session Invalid.");
  return false;

no_site:
  $response->set_http_code(404);
  $response->success("Site data could not be retrieved.");
  log_to_console("Site data could not be retrieved.");
  return false;
}

/**
 * Logs out of the current session.
 * Delete the associated session if one exists.
 */
function logout(&$request, &$response, &$db) {
  // Doesn't logout properly for client???
  //session_destroy();
  $response->set_http_code(200);
  $response->success("Successfully logged out.");
  log_to_console("Logged out");
  return true;
}
?>