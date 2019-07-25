"use strict";

/*****************************************************************************
 * This is the JavaScript file that students need to modify to implement the 
 * password safe application.  The other file, client.js, should be fine 
 * without modification.  That file handles page navigation, event handler
 * binding, token setting/retrieving, preflighting, and provides some 
 * utility functions that this file should use for encoding/decoding strings
 * and making server requests.
 *
 * Please do not use any method other than serverRequest to make requests to
 * the server!  It handles a few things including tokens that you should not
 * reimplement.
 *
 * Most of the functions in this file handle a form submission.  These 
 * are passed as arguments the input/output DOM elements of the form that was
 * submitted.  The "this" keyword for these functions is the form element 
 * itself.  The functions that handle form submissions are:
 *   - login
 *   - signup
 *   - save
 *   - load
 *
 * The other functions are each called for different reasons with different
 * parameters:
 *   - loadSite -- This function is called to populate the input or output 
 *                 elements of the add or load password form.   The function
 *                 takes the site to load (a string) and the form elements
 *                 as parameters.
 *   - logout -- This function is called when the logout link is clicked.
 *               It should clean up any data and inform the server to log
 *               out the user.
 *   - credentials -- This is a utility function meant to be used by the
 *                    login function.  It is not called from other client 
 *                    code (in client.js)!  The purpose of providing the
 *                    outline of this function is to help guide students
 *                    towards an implementation that is not too complicated
 *                    and to give ideas about how some steps can be 
 *                    accomplished.
 *
 * The utility functions in client.js are:
 *   - serverRequest -- Takes the server resource and parameters as arguments
 *                      and returns a promise with two properties:
 *                        * response (a JavaScript response object)
 *                        * json (the decoded data from the server)
 *   - showContent -- Shows the specified page of the application.  This is 
 *                    how student code should redirect the site to other
 *                    pages after a user action.
 *   - status -- displays a status message at the top of the page.
 *   - serverStatus -- Takes the result of the serverRequest promise and
 *                     displays any status messages from it.  This just
 *                     avoids some code duplication.
 *   - bufferToHexString
 *   - hexStringToUint8Array
 *   - bufferToUtf8
 *   - utf8ToUint8Array
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * Look at the MDN documentation for subtle crypto!
 *      https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
 * Also, you may want to use:
 *      https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
 *
 * The subtle crypto error messages are useless.  Typical errors are due to 
 * passing unexpected parameters to the functions.  Take a look at the files
 * from Tutorial 4 for examples of using 
 *      crypto.subtle.importKey
 *      crypto.subtle.sign
 *      crypto.subtle.decrypt
 * You may also be interested in using
 *      crypto.subtle.encrypt
 *      crypto.subtle.digest
 *
 * The most common error is to pass a key or iv buffer that is the wrong size.
 * For AES-CBC, for example, the key must be length 16 or 32 bytes, and the 
 * IV must be 16 bytes.
 *
 * To concatenate two typed Uint8Arrays (a1, a2), you can do the following:
 *      let a3 = new Uint8Array(a1.length + a2.length);
 *      a3.set(a1);
 *      a3.set(a2, a1.length);
 *
 *****************************************************************************/


/**
 * This is an async function that should return the username and password to send
 * to the server for login credentials.
 */ 
async function credentials(username, password) {
  var idResult;
  
  // get any information needed to log in
  idResult = await serverRequest("identify", {"username":username});
  // bail if something went wrong
  if (!idResult.response.ok) {
    serverStatus(idResult);
    console.log("Something went wrong.");
    return 0;
  }

  return idResult.json;
}

function concatenate(a1, a2) {
  var a3 = new Uint8Array(a1.length + a2.length);
  a3.set(a1);
  a3.set(a2, a1.length);
  return a3;
}
/**
 * Called when the user submits the log-in form.
 */
function login(userInput, passInput) {
  // get the form fields
  var username = userInput.value,
      password = passInput.value;
      
  credentials(username, password).then(function(idJson) {
    if (idJson == 0) {
      return;
    }
    // do any needed work with the credentials
    console.log(idJson);
    var challenge_hexstr = idJson.challenge;
    var salt_hexstr = idJson.salt;

    var salt_byte = hexStringToUint8Array(salt_hexstr);
    var challenge_byte = hexStringToUint8Array(challenge_hexstr);
    var password_byte = utf8ToUint8Array(password)
    
    var password_hexstr = bufferToHexString(password_byte);
    var pw_salt_hexstr = password_hexstr.concat(salt_hexstr);
    var pw_salt_byte = hexStringToUint8Array(pw_salt_hexstr);

    console.log(salt_hexstr);
    console.log(challenge_hexstr);
    console.log(password_hexstr);
    console.log(pw_salt_hexstr);

    // compute challenge response
    crypto.subtle.digest("SHA-256", pw_salt_byte).then(function(hash_pw_salt_byte) {
      var hash_pw_salt_hexstr = bufferToHexString(hash_pw_salt_byte);
      var resp_prehash_hexstr = hash_pw_salt_hexstr.concat(challenge_hexstr);
      crypto.subtle.digest("SHA-256", hexStringToUint8Array(resp_prehash_hexstr)).then(function(resp_byte) {
        var resp_hexstr = bufferToHexString(resp_byte);
        // Send a login request to the server.
        serverRequest("login", // resource to call
                      {"username":username, "password":resp_hexstr} // this should be populated with needed parameters
        ).then(function(result) {
          // If the login was successful, show the dashboard.
          if (result.response.ok) {
            showContent("dashboard");
          } else {
            // If the login failed, show the login page with an error message.
            serverStatus(result);
          }
        });
      });
    });
  });
}

function validateEmail(mail) {
  var reg = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/ 
  if (reg.test(myForm.emailAddr.value)) {
    return (true)
  }
  return (false)
}

/**
 * Called when the user submits the signup form.
 */
function signup(userInput, passInput, passInput2, emailInput) {
  // get the form fields
  var username  = userInput.value,
      password  = passInput.value,
      password2 = passInput2.value,
      email     = emailInput.value;

  //gPassword = password;
  // TODO: check that both passwords match?

  // do any preprocessing on the user input here before sending to the server
  // I'm not sure if this is working
  //if (validateEmail(email) === false) {
  //  status("Invalid email");
  //  return;
  //}

  // for now, transmit password in plaintext

  // send the signup form to the server
  serverRequest("signup",  // resource to call
                {"username":username, "password":password, "email":email} // this should be populated with needed parameters
  ).then(function(result) {
    // if everything was good
    if (result.response.ok) {
      // do any work needed if the signup request succeeded

      // go to the login page
      showContent("login");
    }
    // show the status message from the server
    serverStatus(result);
  });
}


/**
 * Called when the add password form is submitted.
 */
function save(siteInput, userInput, passInput) {
  var site       = siteInput.value,
      siteuser   = userInput.value,
      sitepasswd = passInput.value,
      encrypted; // this will need to be populated
  
  encrypted = sitepasswd;
  // send the data, along with the encrypted password, to the server
  serverRequest("save", {"site":site, "siteuser":siteuser, "sitepasswd":encrypted}
  ).then(function(result) {
    if (result.response.ok) {
      // any work after a successful save should be done here

      // update the sites list
      sites("save");
    }
    // show any server status messages
    serverStatus(result);
  });
}

/**
 * Called when a site dropdown is changed to select a site.
 * This can be called from either the save or load page.
 * Note that, unlike all the other parameters to functions in
 * this file, siteName is a string (the site to load) and not
 * a form element.
 */
function loadSite(siteName, siteElement, userElement, passElement) {
  // do any preprocessing here

  serverRequest("load", // the resource to call
                {"site":siteName, "username":username}
  ).then(function(result) {
    if (result.response.ok) {
      // do any work that needs to be done on success
      console.log(result);
    } else {
      // on failure, show the login page and display any server status
      showContent("login");
      serverStatus(result);
    }
  });
}

/**
 * Called when the decrypt password button is pressed.
 */
function load(siteInput, userInput, passInput) {
  // you will need to entirely populate this function
}

/**
 * Called when the logout link is clicked.
 */
function logout() {
  // do any preprocessing needed

  // tell the server to log out
  serverRequest("logout", {}).then(function(result) {
    if (result.response.ok) {
      showContent("login");
    }
    serverStatus(result);
  });
}