<%-- checklogin.jsp

Description:

		Checks for server errors.
		Check user credentials


=============================================================
Date      Name      Modifications
=============================================================
25Sep2002 Babbitt   Basic error checking added.
03Jan2004 Babbitt   Error checking re-enabeled.
04Jan2006 Nichols   Added session attribute "interface" set to "portal"
	so JSPs can check if user logged in to Portal or other interface.
* 2006-07-10 Nichols - removed userRights.loadFromDatabase() to fix race condition bug that was causing
	tab rights to be denied on coding.jsp page, apparently because of partially initialized user rights session bean.
2006-08-02 Nichols - added code to process
		button to login if you have LAN access to the file data for fast file view.  The code detects the
		second button was clicked (name.x parameter), and sets the boolean flag bIsLanLogin which
		is later stored in the User session object for testing by code that needs to know.
2006-08-13 Nichols - added better logging of user login.
2006-08-19 Nichols - added firstname, lastname to User session object.
2008-12-23 Nichols - added jsp aguments to bypass the portal main screen for the efile transfer page
2008-12-24 Nabel - added strcmd != null to fix null pointer exception
2010-03-16 Nichols - changed errorPage from esjsperrorpage.jsp to jsp/pchecklogin_errorpage.jsp;
	CClientBean is modified, using CClientBean.checkStartClient().
2012-08-08 Nichols - non-secure load of roleListBean, user can't see own record.
 2013-04-24 Nichols - new CPasswordBean.verifyUserPassword() or
		CRemoteSessionLogin.getLoggedInUser()
		 or CRemoteSessionLogin.getAuthenticatedUser()
		 or CRecordOperations.getAuthenticatedUser() parameters in calls to support
		control of login auditing.
=============================================================


--%>
<!-- set the jsp import statments -->
<%@ page    language="java"
						errorPage="jsp/pchecklogin_errorpage.jsp"
						import="com.rco.jsp.*,
								java.util.ArrayList,
								java.util.Vector,
								com.rco.client.*,
								com.rco.CORBABase.*"
%>

<%-- Conditionally Instantiate the client beans --%>
<jsp:useBean id="clientBean" class="com.rco.jsp.CClientBean" scope="session"/>
<jsp:useBean id="passwordBean" class="com.rco.jsp.CPasswordBean" scope="page"/>
<jsp:useBean id="userLoginBean" class="com.rco.jsp.CUserLoginBean" scope="page"/>
<jsp:useBean id="monitor" class="java.util.HashMap" scope="application"/>
<jsp:useBean id="roleList" class="com.rco.jsp.CRoleListBean" scope="session"/>


<%-- Start client and check for obvious problems --%>

		<%
//		clientBean.extractAppConfig(application);
		clientBean = CClientBean.checkStartClient(application, session); // -RAN 3/16/10
//		if( !clientBean.startClient() )
		if (clientBean == null) // -RAN 3/16/10
		{
			%>

				<script language= "JavaScript">
						document.location.href="jsp/pchecklogin_errorpage.jsp";
				</script>


		<% } else {     // Validate User credentials
			
			%>
			sessionStorage.clear(); // clear session storage
			<% 

						String userName = request.getParameter("email");
						String password = request.getParameter("password");
						String remoteHost = request.getParameter("clientIP");
						String strcmd = request.getParameter("cmd");
						String strButtonLoginLAN = request.getParameter("img18.x"); // -RAN 8/2/06
						boolean bIsLanLogin = (strButtonLoginLAN != null && strButtonLoginLAN.length() > 0); // -RAN 8/2/06

						String strTarget = "jsp/plogon_selectrole.jsp";
						if (strcmd != null && strcmd.equalsIgnoreCase("filetransfer"))
							strTarget = "jsp/plogon_selectrole.jsp?cmd=filetransfer";


						System.out.println("[pchecklogin.jsp] "
							+ ", strButtonLoginLAN=" + strButtonLoginLAN
							+ ", userName=" + userName
//              + ", password=" + password
							 + ", strTarget=" + strTarget
							+ ", remoteHost=" + remoteHost); // ****** debugging. -RAN 8/13/06

						passwordBean.setName(userName);
						passwordBean.setPassword(password);
						passwordBean.verifyUserPassword(CPasswordBean.getRemoteIpAddress(request), true);

						boolean isValid;

						if(passwordBean.isAuthenticationTrouble())
						{
								%>
									<script language= "JavaScript">
											document.location.href="jsp/pchecklogin_errorpage.jsp"+
												"?er1=<%=passwordBean.authDesc%>"+"&er2=<%=passwordBean.authDetails%>";
									</script>
								<%
						}
						else if(passwordBean.isDbException())
						{
								clientBean.setClientStatusMsg("Please make sure the DATABASE is running and a connection is available.");
								%>
									<script language= "JavaScript">
											document.location.href="jsp/pchecklogin_errorpage.jsp";
									</script>
								<%
						}
						else if (isValid = passwordBean.getIsValid())
						{
							%>
							<script language= "JavaScript">
							var u="<%=userName%>"; 
							var p = "<%=password%>"; 
							// save to session for username/password in url
							sessionStorage.username = u;
							sessionStorage.password = p;
							sessionStorage.isLoggedIn = true;
				            </script>
							<% 
							 String sessionId = session.getId();
							 int userId = passwordBean.getUserId();
							 int groupId = passwordBean.getGroupId();

							IUserStructHolder userData = new IUserStructHolder();
							CClient.getUserServer().getWithoutImage(userId, userId, userData); // -RAN 8/19/06

							 // create user bean and store in session
							 User user = new User(userId, groupId, userName,
								userData.value.firstName, userData.value.lastName,
								 sessionId, remoteHost);

							 //user.setIsLANlogin(bIsLanLogin); // -RAN 8/2/06
							 session.setAttribute("user", user);
							 session.setMaxInactiveInterval(36000);
							 //session.setAttribute("interface", "portal"); // -RAN 1/4/05

							 // create a few other session beans while we are at it
							 CRightsBean userRights = new CRightsBean();
							 userRights.loadFromDatabase(userId);
							 session.setAttribute("userRights", userRights);

							 //monitor.put(user, session);
							 CClient.addClient(sessionId, user);

							 userLoginBean.setUser(user);
							 userLoginBean.logUser(sessionId, remoteHost);

							 //role
							 boolean bAdmin = false;
					 roleList.setUser(user);
//					 roleList.loadFromDatabase( userId );
					 roleList.loadFromDatabase( userId, false ); // need non-secure load because user typically can't see own record. -RAN 8/8/12
							 int numAssigned = roleList.getNumAssigned();
				 ArrayList roleNames = new ArrayList();

				 for (int i = 0; i < numAssigned; i++)  {
							String atemp = roleList.getAssignedName(i);
										if(atemp.indexOf("Admin") >= 0 || atemp.indexOf("ADMIN") >= 0) bAdmin = true;
				 }

							 // add cookie
							 Cookie cookie=new Cookie("login", userName);
							 cookie.setMaxAge(7*24*60*60);
							 response.addCookie(cookie);

							 String sinterface = (String)session.getValue("sinterface");
							 String webCheck = "jsp/plogon_selectrole.jsp";
							 if (sinterface != null && sinterface.equalsIgnoreCase("admin") && !bAdmin)
							 {
									webCheck = "RCOJVCheck.htm";
							 }
							 else if (sinterface == null || sinterface.equalsIgnoreCase("portal") || bAdmin)
							 {
									session.setAttribute("sinterface", "portal"); // -RAN 1/4/05
			if (strcmd != null && strcmd.equalsIgnoreCase("filetransfer"))
			{
										 webCheck = "jsp/plogon_selectrole.jsp?cmd="+strcmd;
									}
			else
			{
										 webCheck = "jsp/plogon_selectrole.jsp";
									}
							 }

								%>

								<script language= "JavaScript">
												document.location.href="<%=webCheck%>";
		<%
		if (strcmd != null && strcmd.equalsIgnoreCase("filetransfer"))
		{
		%>
					//document.location.href="jsp/plogon_selectrole.jsp?cmd=<%=strcmd%>";
		<%
		}
		else
		{
		%>
									//document.location.href="jsp/plogon_selectrole.jsp";
								<%
								 }
								 %>
								</script>
								<%
						}
						else if (passwordBean.isBadIDLVersion() == true)
						{
							 out.println("<PasswordDialog.VerifyPassword> Bad CORBA Version" );
						}
						else
						{
								%>
									<script language= "JavaScript">
											document.location.href="jsp/pchecklogin_errorpage.jsp"+
												"?er1=Invalid Password&er2=Please ensure the CapsLock key is off.";
									</script>
								<%
						}
				}

				%>
