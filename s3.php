<?php
/**
 * PHP Server-Side Example for Fine Uploader S3.
 * Maintained by Widen Enterprises.
 *
 *
 * This example:
 *  - handles non-CORS environment
 *  - handles size validation and no size validation
 *  - handles delete file requests for both DELETE and POST methods
 *  - Performs basic inspections on the policy documents and REST headers before signing them
 *  - Ensures again the file size does not exceed the max (after file is in S3)
 *  - signs policy documents (simple uploads) and REST requests
 *    (chunked/multipart uploads)
 *  - returns a thumbnailUrl in the response for older browsers so thumbnails can be displayed next to the file
 *
 * Requirements:
 *  - PHP 5.3 or newer
 *  - Amazon PHP SDK (only if utilizing the AWS SDK for deleting files or otherwise examining them)
 *
 * If you need to install the AWS SDK, see http://docs.aws.amazon.com/aws-sdk-php-2/guide/latest/installation.html.
 */

error_reporting(E_ERROR | E_PARSE);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE');
header('Access-Control-Max-Age: 1000');
header('Access-Control-Allow-Headers: *');

require('vendor/autoload.php');

use Aws\S3\S3Client;

$expectedMaxSize = '15000000';

$method = getRequestMethod();

parse_str($_SERVER['QUERY_STRING'], $query);

//these variable holds the credential and bucket name of amazon account
$clientPrivateKey = $query['privateKey'];
$serverPublicKey = $query['publicKey'];
$serverPrivateKey = $query['privateKey'];
$expectedBucketName = $query['bucketName'];
$region = $query['region'];


// echo $serverPublicKey;
// echo "\n";
// echo $serverPrivateKey; 

// This second conditional will only ever evaluate to true if
// the delete file feature is enabled
if ($method == "DELETE") {
    deleteObject();
}


// This is all you really need if not using the delete file feature
// and not working in a CORS environment
else if	($method == 'POST') {

    // Assumes the successEndpoint has a parameter of "success" associated with it,
    // to allow the server to differentiate between a successEndpoint request
    // and other POST requests (all requests are sent to the same endpoint in this example).
    // This condition is not needed if you don't require a callback on upload success.

    if (isset($query["success"])) {
        verifyFileInS3(shouldIncludeThumbnail());
    }
    else {
        signRequest();
    }
}

// This will retrieve the "intended" request method.  Normally, this is the
// actual method of the request.  Sometimes, though, the intended request method
// must be hidden in the parameters of the request.  For example, when attempting to
// send a DELETE request in a cross-origin environment in IE9 or older, it is not
// possible to send a DELETE request.  So, we send a POST with the intended method,
// DELETE, in a "_method" parameter.
function getRequestMethod() {
    return $_SERVER['REQUEST_METHOD'];
}

function getS3Client() {
    global $serverPublicKey, $serverPrivateKey, $region;
    $credentials = new Aws\Credentials\Credentials($serverPublicKey, $serverPrivateKey);

    return S3Client::factory(array(
        'credentials' => $credentials,
        'region' => $region,
        'version' => 'latest'
    ));
}

// Only needed if the delete file feature is enabled
function deleteObject() {
    getS3Client()->deleteObject(array(
        'Bucket' => $_REQUEST['bucket'],
        'Key' => $_REQUEST['key']
    ));
}

function signRequest() {
    header('Content-Type: application/json');

    $responseBody = file_get_contents('php://input');
    $contentAsObject = json_decode($responseBody, true);
    $jsonContent = json_encode($contentAsObject);

    signPolicy($jsonContent);
}

function signRestRequest($headersStr) {
    $version = isset($_REQUEST["v4"]) ? 4 : 2;
    if (isValidRestRequest($headersStr, $version)) {
        if ($version == 4) {
            $response = array('signature' => signV4RestRequest($headersStr));
        }
        else {
            $response = array('signature' => sign($headersStr));
        }

        echo json_encode($response);
    }
    else {
        echo json_encode(array("invalid" => true));
    }
}

function isValidRestRequest($headersStr, $version) {
    if ($version == 2) {
        global $expectedBucketName;
        $pattern = "/\/$expectedBucketName\/.+$/";
    }
    else {
        global $expectedHostName;
        $pattern = "/host:$expectedHostName/";
    }

    preg_match($pattern, $headersStr, $matches);

    return count($matches) > 0;
}

function signPolicy($policyStr) {
    global $query;

    $policyObj = json_decode($policyStr, true);

    if (isPolicyValid($policyObj)) {
        $encodedPolicy = base64_encode($policyStr);

        if (isset($query["v4"])) {;
            $response = array('policy' => $encodedPolicy, 'signature' => signV4Policy($encodedPolicy, $policyObj));
        }
        else {
            $response = array('policy' => $encodedPolicy, 'signature' => sign($encodedPolicy));
        }
        echo json_encode($response);

    }
    else {
        echo json_encode(array("invalid" => true));
    }
}

function isPolicyValid($policy) {
    global $expectedMaxSize, $expectedBucketName;

    $conditions = $policy["conditions"];
    $bucket = null;
    $parsedMaxSize = null;

    for ($i = 0; $i < count($conditions); ++$i) {
        $condition = $conditions[$i];

        if (isset($condition["bucket"])) {
            $bucket = $condition["bucket"];
        }
        else if (isset($condition[0]) && $condition[0] == "content-length-range") {
            $parsedMaxSize = $condition[2];
        }
    }

    return $bucket == $expectedBucketName && $parsedMaxSize == (string)$expectedMaxSize;
}

function sign($stringToSign) {
    global $clientPrivateKey;

    return base64_encode(hash_hmac(
        'sha1',
        $stringToSign,
        $clientPrivateKey,
        true
    ));
}

function signV4Policy($stringToSign, $policyObj) {
    global $clientPrivateKey;

    foreach ($policyObj["conditions"] as $condition) {
        if (isset($condition["x-amz-credential"])) {
            $credentialCondition = $condition["x-amz-credential"];
        }
    }

    $pattern = "/.+\/(.+)\\/(.+)\/s3\/aws4_request/";
    preg_match($pattern, $credentialCondition, $matches);

    $dateKey = hash_hmac('sha256', $matches[1], 'AWS4' . $clientPrivateKey, true);
    $dateRegionKey = hash_hmac('sha256', $matches[2],  $dateKey, true);
    $dateRegionServiceKey = hash_hmac('sha256', 's3', $dateRegionKey, true);
    $signingKey = hash_hmac('sha256', 'aws4_request', $dateRegionServiceKey, true);

    return hash_hmac('sha256', $stringToSign, $signingKey);
}

function signV4RestRequest($rawStringToSign) {
    global $clientPrivateKey;

    $pattern = "/.+\\n.+\\n(\\d+)\/(.+)\/s3\/aws4_request\\n(.+)/s";
    preg_match($pattern, $rawStringToSign, $matches);

    $hashedCanonicalRequest = hash('sha256', $matches[3]);
    $stringToSign = preg_replace("/^(.+)\/s3\/aws4_request\\n.+$/s", '$1/s3/aws4_request'."\n".$hashedCanonicalRequest, $rawStringToSign);

    $dateKey = hash_hmac('sha256', $matches[1], 'AWS4' . $clientPrivateKey, true);
    $dateRegionKey = hash_hmac('sha256', $matches[2], $dateKey, true);
    $dateRegionServiceKey = hash_hmac('sha256', 's3', $dateRegionKey, true);
    $signingKey = hash_hmac('sha256', 'aws4_request', $dateRegionServiceKey, true);

    return hash_hmac('sha256', $stringToSign, $signingKey);
}

// This is not needed if you don't require a callback on upload success.
function verifyFileInS3($includeThumbnail) {
    global $expectedMaxSize;

    $bucket = $_POST["bucket"];
    $key = $_POST["key"];

    // If utilizing CORS, we return a 200 response with the error message in the body
    // to ensure Fine Uploader can parse the error message in IE9 and IE8,
    // since XDomainRequest is used on those browsers for CORS requests.  XDomainRequest
    // does not allow access to the response body for non-success responses.
    if (isset($expectedMaxSize) && getObjectSize($bucket, $key) > $expectedMaxSize) {
        // You can safely uncomment this next line if you are not depending on CORS
        header("HTTP/1.0 500 Internal Server Error");
        deleteObject();
        echo json_encode(array("error" => "File is too big!", "preventRetry" => true));
    }
    else {
        $link = getTempLink($bucket, $key);
        $response = array("tempLink" => $link);

        if ($includeThumbnail) {
            $response["thumbnailUrl"] = $link;
        }

        echo json_encode($response);
    }
}

// Provide a time-bombed public link to the file.
function getTempLink($bucket, $key) {
    $client = getS3Client();

    $cmd = $client->getCommand('GetObject', array(
        'Bucket' => $bucket,
        'Key' => $key
    ));

    $request = $client->createPresignedRequest($cmd, '+15 minutes');

    return (string)$request->getUri();
}

function getObjectSize($bucket, $key) {
    $objInfo = getS3Client()->headObject(array(
        'Bucket' => $bucket,
        'Key' => $key
    ));
    return $objInfo['ContentLength'];
}

// Return true if it's likely that the associate file is natively
// viewable in a browser.  For simplicity, just uses the file extension
// to make this determination, along with an array of extensions that one
// would expect all supported browsers are able to render natively.
function isFileViewableImage($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $viewableExtensions = array("jpeg", "jpg", "gif", "png");

    return in_array($ext, $viewableExtensions);
}

// Returns true if we should attempt to include a link
// to a thumbnail in the uploadSuccess response.  In it's simplest form
// (which is our goal here - keep it simple) we only include a link to
// a viewable image and only if the browser is not capable of generating a client-side preview.
function shouldIncludeThumbnail() {
    $filename = $_POST["name"];
    $isPreviewCapable = $_POST["isBrowserPreviewCapable"] == "true";
    $isFileViewableImage = isFileViewableImage($filename);

    return !$isPreviewCapable && $isFileViewableImage;
}
?>