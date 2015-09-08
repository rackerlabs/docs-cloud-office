Introduction
============

The Rackspace Email Rest API provides most of the functions of the
Control Panel through a REST-based `web
API <http://en.wikipedia.org/wiki/Web_service>`__. Whether it is adding
a new customer account, adding mailboxes, or any other of the supported
features the API allows your application to administer the changes
regardless of your application's language or nature. For more
information on RESTful web services refer to the following sites:

`Paul James's Homepage: A RESTful Web service, an
example <http://www.peej.co.uk/articles/restfully-delicious.html>`__

`Wikipedia: Representational State Transfer - External
Links <http://en.wikipedia.org/wiki/Representational_State_Transfer#External_links>`__

The API is accessible to all with access to Control Panel, including
resellers, business customers, enterprise customers, and indirect
customers. However, not all operations are available to non-resellers.
See the `Operations <Rest_API#Operations>`__ section for more details.

The Rackspace Email Soap API Homepage has been moved to
`here <Soap_API>`__.

Operations
==========

The following pages detail the operations that the API supports. The
operations are grouped into sections based on the entity/object types
that each operation interacts with. Non-resellers do not have access to
all functions.

+--------------------------+--------------------------+--------------------------+
| Resource                 | Example URI              | Business User Access     |
+==========================+==========================+==========================+
| `Customer <Customer_(Res | /customers/123456789     | `Create Login            |
| t_API)>`__               |                          | Tokens <Customer_(Rest_A |
|                          |                          | PI)#Create_Login_Tokens> |
|                          |                          | `__                      |
+--------------------------+--------------------------+--------------------------+
| `Admin <Admin_(Rest_API) | /customers/123456789/adm | All                      |
| >`__                     | ins/my\_admin            |                          |
+--------------------------+--------------------------+--------------------------+
| `Domain <Domain_(Rest_AP | /customers/123456789/dom | `Index <Domain_(Rest_API |
| I)>`__                   | ains/example.com         | )#Index>`__,             |
|                          |                          | `Show <Domain_(Rest_API) |
|                          |                          | #Show>`__,               |
|                          |                          | `Split Domain            |
|                          |                          | Routing <Domain_(Rest_AP |
|                          |                          | I)#Split_Domain_Routing> |
|                          |                          | `__,                     |
|                          |                          | `Archiving SSO Login     |
|                          |                          | URL <Domain_(Rest_API)#A |
|                          |                          | rchiving_SSO_Login_URL>` |
|                          |                          | __,                      |
|                          |                          | `Domain Public           |
|                          |                          | Folders <Domain_(Rest_AP |
|                          |                          | I)#Domain_Public_Folders |
|                          |                          | _.28Reseller_Only.29>`__ |
|                          |                          | ,                        |
|                          |                          | `Email                   |
|                          |                          | Everyone <Domain_(Rest_A |
|                          |                          | PI)#Domain_Email_Everyon |
|                          |                          | e>`__,                   |
|                          |                          | `Catch-All               |
|                          |                          | Address <Domain_(Rest_AP |
|                          |                          | I)#Show_Domain_Catch-All |
|                          |                          | _Address>`__             |
+--------------------------+--------------------------+--------------------------+
| `Domain Spam             | /customers/123456789/dom | All                      |
| Settings <Domain_Spam_(R | ains/example.com/spam/se |                          |
| est_API)>`__             | ttings                   |                          |
+--------------------------+--------------------------+--------------------------+
| `Rackspace Email         | /customers/123456789/dom | All                      |
| Mailbox <Rackspace_Mailb | ains/example.com/rs/mail |                          |
| ox_(Rest_API)>`__        | boxes/john.smith         |                          |
+--------------------------+--------------------------+--------------------------+
| `Rackspace Email Mobile  | /customers/123456789/dom | All                      |
| Sync <Rackspace_Email_Mo | ains/example.com/mobiles |                          |
| bile_Sync_(Rest_API)>`__ | ync                      |                          |
+--------------------------+--------------------------+--------------------------+
| `Rackspace Email Mailbox | /customers/123456789/dom | All                      |
| Spam                     | ains/example.com/rs/mail |                          |
| Settings <Rackspace_Mail | boxes/john.smith/spam    |                          |
| box_Spam_(Rest_API)>`__  |                          |                          |
+--------------------------+--------------------------+--------------------------+
| `Rackspace Storage       | /customers/123456789/dom | All                      |
| Notification             | ains/example.com/rs/stor |                          |
| Settings <Rackspace_Stor | ageNotification          |                          |
| age_Notification_(Rest_A |                          |                          |
| PI)>`__                  |                          |                          |
+--------------------------+--------------------------+--------------------------+
| `Rackspace Email         | /customers/123456789/dom | All                      |
| Alias <Rackspace_Alias(R | ains/example.com/rs/mail |                          |
| est_API)>`__             | boxes/john.smith/alias   |                          |
+--------------------------+--------------------------+--------------------------+
| `Exchange                | /customers/123456789/dom | All                      |
| Mailbox <Exchange_Mailbo | ains/example.com/ex/mail |                          |
| x_(Rest_API)>`__         | boxes/john.smith         |                          |
+--------------------------+--------------------------+--------------------------+
| `Exchange Mailbox Spam   | /customers/123456789/dom | All                      |
| Settings <Exchange_Mailb | ains/example.com/ex/mail |                          |
| ox_Spam_(Rest_API)>`__   | boxes/john.smith/spam    |                          |
+--------------------------+--------------------------+--------------------------+
| `Exchange                | /customers/123456789/dom | All                      |
| Contact <Exchange_Contac | ains/example.com/ex/cont |                          |
| t_(Rest_API)>`__         | acts/john.smith          |                          |
+--------------------------+--------------------------+--------------------------+
| `Exchange Distribution   | /customers/123456789/dom | All                      |
| List <Exchange_Distribut | ains/example.com/ex/dist |                          |
| ion_List_(Rest_API)>`__  | ributionlists/group.name |                          |
+--------------------------+--------------------------+--------------------------+
| `Exchange Resource       | /customers/123456789/dom | All                      |
| Mailbox <Exchange_Resour | ains/example.com/ex/reso |                          |
| ce_Mailbox_(Rest_API)>`_ | urces/conference.room    |                          |
| _                        |                          |                          |
+--------------------------+--------------------------+--------------------------+
| `Exchange                | /customers/123456789/dom | All                      |
| Lync <Exchange_Lync_(Res | ains/example.com/ex/lync |                          |
| t_API)>`__               | /users                   |                          |
+--------------------------+--------------------------+--------------------------+
| `Exchange Public         | /customers/123456789/dom | All                      |
| Folders <Exchange_Public | ains/example.com/ex/publ |                          |
| _Folders_(Rest_API)>`__  | icFolders                |                          |
+--------------------------+--------------------------+--------------------------+
| `SharePoint <SharePoint_ | /customers/123456789/sha | `Show <SharePoint_(Rest_ |
| (Rest_API)>`__           | repoint/settings         | API)#Show>`__            |
+--------------------------+--------------------------+--------------------------+

The examples shown in the operation pages are written in Ruby and
extensively use the helper functions shown in the Ruby Examples below.

Quick Start
===========

**What you need:**

-  A Rackspace Email and Apps Control Panel admin account
-  A HTTP class library that supports TLS and the HTTP methods: GET,
   POST, PUT, DELETE.

**Making your first API call, an Show Customer request:**

#. Obtain your API keys

   :\* Login to `Control Panel <https://cp.rackspace.com>`__

   :\* Click the drop down in the top right next to your admin
   id/account number.

   :\* Click Admins & Contacts

   :\* Click API Keys

#. Set up your client's HTTP request

   :\* Set up your client to make calls to a URL beginning with
   https://api.emailsrvr.com/v1.

   :\* Populate the Accept, User-Agent and X-Api-Signature HTTP request
   headers correctly. This is explained in detail
   `here <#HTTP_Headers>`__.

#. Make a GET request to /customers/me.

   :\* The complete URI will be
   https://api.emailsrvr.com/v1/customers/me/domains. Use your HTTP
   library to retrieve the HTTP response code, 'x-error-message' HTTP
   response header and HTTP response body so that they may be displayed
   to help debug and determine success.

**From here:**

-  Learn about the operations you'll be implementing at the subpages
   `here <#Operations>`__.

Accessing the API
=================

Your application should need to make HTTP requests over TLS (HTTPS) to
our API servers. Most programming languages have this functionality
built into their core libraries. In addition to the common GET and POST
HTTP methods, the library used will also need to support PUT and DELETE.

For some language's libraries, simply using an URL that starts with
https:// will cause the library to use TLS. In some other libraries
however some options specific to the library may have to be configured
to utilize TLS.

All API calls should be directed to a URL in the following format:

::

    https://api.emailsrvr.com/(version)/(resource)

Example:

::

    https://api.emailsrvr.com/v1/customers/12345678/domains/customerbusiness.com

Versions
--------

+--------------------------+--------------------------+--------------------------+
| *Supported Versions*     | *URL*                    | *Version Documentation*  |
+==========================+==========================+==========================+
| v1 (current)             | https://api.emailsrvr.co | http://api-wiki.apps.rac |
|                          | m/v1/                    | kspace.com/api-wiki/inde |
|                          |                          | x.php/Main_Page          |
+--------------------------+--------------------------+--------------------------+

The API version number is a component of the URL that is used to access
the API. For example, to access the root of the API, the URL is
https://api.emailsrvr.com/v1/. Bug fixes and minor non-breaking changes
will be made without changing the version number. When major features or
breaking changes are introduced, the version number will be incremented.
It is not yet determined how many versions are going to be supported at
any one time.

**Using the discontinued v0 API?**

-  If your client consumes v0 of the Admin REST API for Exchange
   Distribution Lists or Exchange Resource Mailboxes routes, the client
   must be updated to consume the new behavior in v1.
-  If your client does not consume the v0 Admin REST API for Exchange
   Distribution Lists and Exchange Resource Mailboxes, you simply need
   to update the base URL (i.e. https://api.emailsrvr.com/v0/\ …) from
   v0 to v1. There were no changes to the behavior of the other entities
   in the API, only their location changed.

+--------------------------------------+--------------------------------------+
| *Non-breaking Changes*               | *Breaking Changes*                   |
+======================================+======================================+
| Adding new fields or attributes to   | Changing or deleting any fields in   |
| form fields sent                     | form fields sent                     |
+--------------------------------------+--------------------------------------+
| Adding fields in returned data       | Changing or removing fields in       |
|                                      | returned data                        |
+--------------------------------------+--------------------------------------+
|                                      | Changing the URI of any resource     |
+--------------------------------------+--------------------------------------+

Authentication
--------------

To gain access to the API, your request must include a properly
constructed X-Api-Signature HTTP header. Details on what to put in the
header are below. To construct the header, you must have the following
keys that are generated from the `API
Keys <https://cp.rackspace.com/MyAccount/Administrators/ApiKeys>`__
page.

+--------------------------+--------------------------+--------------------------+
| Key Name                 | Description              | Example                  |
+==========================+==========================+==========================+
| User Key                 | A public key that        | *eGbq9/2hcZsRlr1JV1Pi*   |
|                          | corresponds to your      |                          |
|                          | admin id                 |                          |
+--------------------------+--------------------------+--------------------------+
| Secret Key               | A shared secret key      | *QHOvchm/40czXhJ1OxfxK7j |
|                          |                          | DHr3t*                   |
+--------------------------+--------------------------+--------------------------+

An unsuccessful authentication will result in a 403 HTTP code.

X-Api-Signature Header
~~~~~~~~~~~~~~~~~~~~~~

| Format is as follows: <'''User Key'''>:<'''Timestamp'''>:<'''SHA1
  Hash'''>
|  Example:
  *eGbq9/2hcZsRlr1JV1Pi:20010317143725:46VIwd66mOFGG8IkbgnLlXnfnkU=*

Remember to include the colons between the data strings!

| 
|  **User Key**:
|  This is the public key issued by the Control Panel browser interface.

| 
|  **Timestamp**:
|  The format is YYYYMMDDHHmmss. All values besides year are zero-padded
  to two spaces. For example, March 08th 2001 at 2:37.25pm would be
  *20010308143725*.

+--------------------------------------+--------------------------------------+
| YYYY                                 | Four-digit year                      |
+--------------------------------------+--------------------------------------+
| MM                                   | Month                                |
+--------------------------------------+--------------------------------------+
| DD                                   | Day                                  |
+--------------------------------------+--------------------------------------+
| HH                                   | Hour in 24h format                   |
+--------------------------------------+--------------------------------------+
| mm                                   | Minute                               |
+--------------------------------------+--------------------------------------+
| ss                                   | Second                               |
+--------------------------------------+--------------------------------------+

**SHA1 Hash**:

A SHA1 (Secure Hash Algorithm) hash must be applied to a string with the
following information:

<'''User Key'''><'''User Agent'''><'''Timestamp'''><'''Secret Key'''>

| Note that the 'User Agent' must be the exact same as what is specified
  in the User-Agent HTTP header. Using the above example data, the
  string before hashing is:
|  *eGbq9/2hcZsRlr1JV1PiRackspace Management
  Interface20010308143725QHOvchm/40czXhJ1OxfxK7jDHr3t*

| Resulting base-64 SHA1 Hash:
|  *46VIwd66mOFGG8IkbgnLlXnfnkU=*

Be sure to encode the binary hash, not the hex hash, into base-64. The
resulting string should be 28 characters long.

Using the API
=============

Requests
--------

HTTP requests should be sent to the server with the correct URL, HTTP
method, HTTP headers and form data (if needed). The URL specifies the
resource, the HTTP method specifies what operation is done on the
resource, and form data is used to specify the details of the resource
when the resource is added or edited.

The URLs, corresponding HTTP methods, and necessary form data for the
desired operations are detailed in the `operation
pages <#Operations>`__.

If you're getting the HTTP status code 417 see `Handling HTTP code 417:
Expectation failed <Handling_HTTP_code_417:_Expectation_failed>`__

URL
~~~

The URLs are specifies the resource or resource collection. Objects are
organized in a tree collection, starting with customers at the top, then
domains, then domain objects next (such as mailboxes, contacts, and
distribution lists) and so on. The URLs of the resources and collections
accessible are found on the operation pages.

HTTP Method
~~~~~~~~~~~

It is the HTTP method that specifies what operation will be done on the
resource. For example, to get the details of a mailbox a HTTP GET will
be done on
/customers/12345678/domains/example.com/ex/mailboxes/john.smith. If the
mailbox does not exist, a HTTP POST to the same URL with the necessary
form data will add the mailbox. Then, a HTTP PUT to the same URL will
edit mailbox. And to delete the mailbox, an HTTP DELETE would be used.

The types of operations a certain method performs is outlined below.

*HTTP Method*

*Operations*

*Response*

rowspan=2\|GET

Index - returns a list of the resources

rowspan=2\|XML or JSON formatted data

Show - returns the details of the resource

POST

Add - adds a new resource

rowspan=3\|Response code and error message (if applicable) only

PUT

Edit - changes the details of the resource

DELETE

Delete - deletes the resource

HTTP Headers
~~~~~~~~~~~~

All requests to the API must then include HTTP headers with the
following information:

+--------------------------+--------------------------+--------------------------+
| *Header Name*            | *Description*            | *Example Header Value*   |
+==========================+==========================+==========================+
| Accept                   | The requested content    | *text/xml*               |
|                          | type (required for Index |                          |
|                          | and Show actions). Fill  |                          |
|                          | this with either         |                          |
|                          | 'text/xml' or            |                          |
|                          | 'application/json'. See  |                          |
|                          | `Response                |                          |
|                          | Formats <#Formats>`__    |                          |
+--------------------------+--------------------------+--------------------------+
| User-Agent               | An identifier you choose | *Rackspace Management    |
|                          | for your client software | Interface*               |
+--------------------------+--------------------------+--------------------------+
| X-Api-Signature          | An authentication string | *eGbq9/2hcZsRlr1JV1Pi:20 |
|                          | explained in detail      | 010317143725:HKUn0aajpSD |
|                          | `here <#X-Api-Signature_ | x7qqGK3vqzn3FglI=*       |
|                          | Header>`__               |                          |
+--------------------------+--------------------------+--------------------------+

Form Data
~~~~~~~~~

When using Add and Edit operations, the details of the resource are sent
to the API server via HTTP form data. Your HTTP library should include
methods for sending form data along with an HTTP request. The library
should by default send the data in the HTTP request body using the
'application/x-www-form-urlencoded' data format.

Index Filter/Search
~~~~~~~~~~~~~~~~~~~

The results of Index actions can be filtered/searched. The index URLs
can take either one of the query strings: "?startswith=xx" or
"?contains=xx," where "xx" is the key word. If the request specifies
more than one of these two query strings, a 400 HTTP error will be
returned. Different fields will be searched depending on the resource
type, see below.

Note that "0-9" is a reserved key word for query string "startswith." It
represents any result starting with numbers.

+--------------------------------------+--------------------------------------+
| *Index Actions*                      | *Where the key word will be          |
|                                      | searched*                            |
+======================================+======================================+
| Customer                             | Customer name, account number,       |
|                                      | reference number                     |
+--------------------------------------+--------------------------------------+
| Domain                               | Domain name                          |
+--------------------------------------+--------------------------------------+
| Mailbox                              | Mailbox name, mailbox display name,  |
|                                      | custom ID field                      |
+--------------------------------------+--------------------------------------+
| Contact                              | Contact display name, external email |
+--------------------------------------+--------------------------------------+
| Group                                | Group name, group display name       |
+--------------------------------------+--------------------------------------+
| Mobile Service                       | Associated mailbox name, mailbox     |
|                                      | display name                         |
+--------------------------------------+--------------------------------------+
| Lync Users                           | Mailbox name (NOTE: Does not support |
|                                      | the startsWith search parameter)     |
+--------------------------------------+--------------------------------------+

Throttling
~~~~~~~~~~

The server limits the number of requests allowed per user in a certain
period of time. The number of requests made are logged per minute. Calls
that were made correctly with a user's API key, but not completed for
any reason, including those exceeding the throttle limit, are included
in this count.

If a user is over the throttling limit then a 403 HTTP code will be
returned with an "Exceeded request limits" message.

+--------------------------------------+--------------------------------------+
| *Operation Category*                 | *Request Limit*                      |
+======================================+======================================+
| GET                                  | 60 per minute                        |
+--------------------------------------+--------------------------------------+
| PUT, POST, DELETE                    | 30 per minute                        |
+--------------------------------------+--------------------------------------+
| POST, PUT, DELETE on a domain        | 2 per minute                         |
+--------------------------------------+--------------------------------------+
| POST, DELETE on alternate domains    | 2 per minute                         |
+--------------------------------------+--------------------------------------+
| Enabling public folders for a domain | 1 per 5 minutes                      |
+--------------------------------------+--------------------------------------+

Examples
~~~~~~~~

Index of Exchange Mailboxes:

::

    Hypertext Transfer Protocol
        GET /v1/customers/12345678/domains/example.com/ex/mailboxes?size=100&offset=100 HTTP/1.1
        Host: api.emailsrvr.com
        User-Agent: Rackspace Management Interface
        X-Api-Signature: eGbq9/2hcZsRlr1JV1Pi:20010317143725:HKUn0aajpSDx7qqGK3vqzn3FglI=
        Accept: text/xml

Adding New Exchange Mailbox:

::

    Hypertext Transfer Protocol
        POST /v1/customers/12345678/domains/example.com/ex/mailboxes/john.smith HTTP/1.1
        Host: api.emailsrvr.com
        User-Agent: Rackspace Management Interface
        X-Api-Signature: eGbq9/2hcZsRlr1JV1Pi:20010317143725:HKUn0aajpSDx7qqGK3vqzn3FglI=
        Content-Length: 53
            [Content length: 53]
        Content-Type: application/x-www-form-urlencoded
     
    Line-based text data: application/x-www-form-urlencoded
        size=2048&displayName=John%20Smith&password=abcABC123

Responses
---------

HTTP Status Code
~~~~~~~~~~~~~~~~

On a successfully executed request, a 200 HTTP Code is returned. If the
request was unsuccessful however, an HTTP error code in the 400s or 500s
will be returned.

HTTP Response Body
~~~~~~~~~~~~~~~~~~

If the request is an Index or Show request, the request data will be
returned in the format specified in the HTTP Body.

Formats
^^^^^^^

Requests for data (index and show requests) are returned with XML or
JSON data based on what your application populates the `HTTP Accept
headers <#HTTP_Headers>`__ with.

For XML, populate the header with 'text/xml' (ex: Headers!["Accept"] =
"text/xml"). The XML document returned will conform to a published XSD
(XML Schema Document). There are many ways to parse the data in an XML
document, but we have found that the
`XPath <http://www.w3schools.com/XPath/default.asp>`__ tree-style
traversal has served our purposes. In any case, your application will
likely need to use a class library for your chosen method.

For JSON, populate the header with 'application/json' (ex:
Headers!["Accept"] = "application/json"). As with XML, a library will
likely be needed to parse the data.

HTTP Headers
~~~~~~~~~~~~

The only data returned in the header is the error message (if any).

+--------------------------+--------------------------+--------------------------+
| *Header Name*            | *Description*            | *Example Header Value*   |
+==========================+==========================+==========================+
| x-error-message          | The error message. See   | Missing required field:  |
|                          | `Errors <#Errors>`__.    | name                     |
+--------------------------+--------------------------+--------------------------+

Errors
~~~~~~

See `Errors <Errors>`__.

Paging
~~~~~~

The results of Index actions are split into pages to lessen potentially
high resource usage. The index URLs have a query string with parameters
in the format "?size=xx&offset=xx." If a query parameter is omitted, the
default value is used.

+--------------------+--------------------+--------------------+--------------------+
| *Query Parameter*  | *Default*          | *Maximum*          | *Notes*            |
+====================+====================+====================+====================+
| size               | 50                 | 250                | This is the number |
|                    |                    |                    | of elements per    |
|                    |                    |                    | page.              |
+--------------------+--------------------+--------------------+--------------------+
| offset             | 0                  | N/A                | This is the number |
|                    |                    |                    | of items to offset |
|                    |                    |                    | away from the      |
|                    |                    |                    | first item in the  |
|                    |                    |                    | list.              |
+--------------------+--------------------+--------------------+--------------------+

Example
^^^^^^^

A PHP Example of paging can be found `here <PHP_Examples_(Rest_API)>`__.

Examples
~~~~~~~~

::

    HTTP/1.1 200 OK
    Cache-Control: private
    Content-Type: text/xml; charset=utf-8
    Server: Microsoft-IIS/7.0
    Date: Fri, 04 Dec 2009 19:08:11 GMT
    Content-Length: 430

    <?xml version="1.0" encoding="utf-8"?>
    <domainList xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="urn:xml:domainList">
      <offset>0</offset>
      <size>50</size>
      <total>1</total>
      <domains>
        <domain>
          <name>customer.com</name>
          <accountNumber>123456</accountNumber>
          <serviceType>rsemail</serviceType>
        </domain>
      </domains>
    </domainList>

::

    HTTP/1.1 404 Not Found
    Cache-Control: private
    Server: Microsoft-IIS/7.0
    x-error-message: Customer Not Found
    Date: Fri, 04 Dec 2009 19:13:59 GMT
    Content-Length: 0

::

    HTTP/1.1 400 Bad Request
    Cache-Control: private
    Server: Microsoft-IIS/7.0
    x-error-message: Missing required field: type
    Date: Fri, 04 Dec 2009 19:17:29 GMT
    Content-Length: 0

Examples
========

Ruby
----

This examples is written in `Ruby <http://www.ruby-lang.org/en/>`__. To
make the examples shorter, helper methods have been written. These
methods are part of a NetMethods module. The contents of the NetMethods
module is listed below.

::

    require  'server.rb'

    server = Server.new

    response = server.get  '/customers', server.xml_format

    #fields = Hash['serviceType' =>  'exchange', 'exchangeMaxNumMailboxes' => '4']
    #response =  server.post '/customers/me/domains/newdomain.com', fields

    puts response.code
    puts response['x-error-message']
    puts response.body

::

    require 'test/unit/assertions'
    require 'net/http'
    require 'date'
    require 'date/format'
    require 'digest/sha1'
    require 'base64'
    require 'time'

    class Server
      include Test::Unit::Assertions
      
      def initialize(server='api.emailsrvr.com', version_prefix='/v1', user_key='xxxxxxxxxxxxxxxxxxxx', secret_hash='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        @server = server
        @version_prefix = version_prefix
        @user_key = user_key
        @secret_hash = secret_hash
      end
      
    # Response Type Enums

      def xml_format
        'text/xml'
      end
      
      def json_format
        'application/json'
      end

    #
    # HTTP Request Verbs
    #  
      def get(url_string, format)
        uri = full_uri(url_string)
        headers = prepared_headers
        headers['Accept'] = format
        request = Net::HTTP::Get.new(request_uri(uri), headers)
        http_response = make_request request, uri
      end
      
      def delete(url_string)
        uri = full_uri(url_string)
        request = Net::HTTP::Delete.new(request_uri(uri), prepared_headers)
        http_response = make_request request, uri
      end
      
      def put(url_string, fields_hash)
        uri = full_uri(url_string)
        request = Net::HTTP::Put.new(request_uri(uri), prepared_headers)
        request.set_form_data(fields_hash)
        http_response = make_request request, uri
      end
      
      def post(url_string, fields_hash)
        uri = full_uri(url_string)
        request = Net::HTTP::Post.new(request_uri(uri), prepared_headers)
        request.set_form_data(fields_hash)
        http_response = make_request request, uri
      end
      
    #
    # HTTP Request Helpers
    # 
      def make_request request, uri
        response = Net::HTTP::start(uri.host, uri.port)  do |http|
          http.request request
        end
        
        response
      end
      
      def full_uri url_string
        URI.parse('http://' + @server + @version_prefix + url_string)
      end
      
      def request_uri uri
        request = uri.path
        if ! uri.query.nil?
          request = request + '?' + uri.query
        end
        request
      end
      
      def prepared_headers
        headers = Hash.new
        headers.merge! headers_auth_creds(@user_key, @secret_hash)
        headers['Accept'] = xml_format
        headers
      end
      
      def headers_auth_creds apiKey, secretKey
        userAgent = 'Ruby Test Client'
        timestamp = DateTime.now.strftime('%Y%m%d%H%M%S')
        
        data_to_sign = apiKey + userAgent + timestamp + secretKey
        
        hash = Base64.encode64(Digest::SHA1.digest(data_to_sign))
        signature = apiKey + ":" + timestamp + ":" + hash
        
        headers = Hash['User-Agent' => userAgent, 'X-Api-Signature' => signature]
      end
    end

C#
--

This examples is written in
`C# <http://msdn.microsoft.com/en-us/vcsharp/default.aspx>`__.

::

    using System;
    using System.IO;
    using System.Net;
    using System.Security.Cryptography;
    using System.Text;

    namespace RestApiClient
    {
        public class RestApiClient
        {
            private HttpWebRequest request;
            private HttpWebResponse response;
            private string baseUrl;
            private string apiKey;
            private string secretKey;

            public RestApiClient(string baseUrl, string apiKey, string secretKey)
            {
                this.baseUrl = baseUrl;
                this.apiKey = apiKey;
                this.secretKey = secretKey;
            }

            public HttpWebResponse Get(string url, string format)
            {
                this.request = (System.Net.HttpWebRequest)HttpWebRequest.Create(this.baseUrl + url);
                request.Method = "GET";
                SignMessage();
                AssignFormat(format);
                return GetResponseContent();
            }

            public HttpWebResponse Post(string url, string data, string format)
            {
                this.request = (System.Net.HttpWebRequest)HttpWebRequest.Create(this.baseUrl + url);
                request.Method = "POST";
                SignMessage();
                AssignFormat(format);
                SendFormData(data);
                return GetResponseContent();
            }

            public HttpWebResponse Put(string url, string data, string format)
            {
                this.request = (System.Net.HttpWebRequest)HttpWebRequest.Create(this.baseUrl + url);
                request.Method = "PUT";
                SignMessage();
                AssignFormat(format);
                SendFormData(data);
                return GetResponseContent();
            }

            public HttpWebResponse Delete(string url, string format)
            {
                this.request = (System.Net.HttpWebRequest)HttpWebRequest.Create(this.baseUrl + url);
                request.Method = "DELETE";
                SignMessage();
                AssignFormat(format);
                return GetResponseContent();
            }

            private void SendFormData(string data)
            {
                UTF8Encoding encoding = new UTF8Encoding();
                byte[] byteData = encoding.GetBytes(data);
                this.request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = byteData.Length;
                Stream requestStream = request.GetRequestStream();
                requestStream.Write(byteData, 0, byteData.Length);
                requestStream.Close();
            }

            private HttpWebResponse GetResponseContent()
            {
                try
                {
                    return (HttpWebResponse)request.GetResponse();
                }
                catch (WebException e)
                {
                    return (HttpWebResponse)e.Response;
                }

            }

            private void SignMessage()
            {
                var userAgent = "C# Client Library";
                this.request.UserAgent = userAgent;
                var dateTime = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
                var dataToSign = apiKey + userAgent + dateTime + secretKey;
                var hash = SHA1.Create();
                var signedBytes = hash.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
                var signature = Convert.ToBase64String(signedBytes);

                request.Headers["X-Api-Signature"] = apiKey + ":" + dateTime + ":" + signature;
            }

            private void AssignFormat(string format)
            {
                this.request.Accept = format;
            }
        }
    }

PHP
---

The PHP Example can be found `here <PHP_Examples_(Rest_API)>`__.
