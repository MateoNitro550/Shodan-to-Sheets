const fs = require("fs");
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const querystring = require("querystring");

// --- Configuration ---
const shodan_search_api_base = new URL("https://api.shodan.io/shodan/host/search");
const shodan_host_api_base = "https://api.shodan.io/shodan/host/";
const credentials = require("./auth/credentials.json");
const port = process.env.PORT || 3000;
const shodan_api_key = process.env.SHODAN_API_KEY || credentials.shodan_api_key;
const google_client_id = process.env.GOOGLE_CLIENT_ID || credentials.google_client_id;
const google_client_secret = process.env.GOOGLE_CLIENT_SECRET || credentials.google_client_secret;
const google_redirect_uri = `http://localhost:${port}/callback`;
const google_scope = "https://www.googleapis.com/auth/spreadsheets";
const request_headers = {
    "Accept": "application/json",
};
const response_headers = {
    "Content-Type": "text/html; charset=utf-8",
};
const limit = 10;
const session = new Map();
const sheet_columns = [
    "run_timestamp",
    "timestamp",
    "shodan_query",
    "ip_str",
    "port",
    "transport",
    "isp",
    "location.country_name",
    "location.city",
    "hostnames",
    "domains",
    "product",
    "version",
    "os",
    "vulns",
    "ftp",
    "http",
    "smb",
    "ssh",
    "data",
];

// --- Server Setup ---
const server = http.createServer();
server.on("request", handle_request);
server.on("listening", handle_listen);
server.listen(port);

// --- Handlers ---
function handle_listen(){
    console.log(`Now Listening on Port ${port}`);
}

function handle_request(req, res){
    console.log(`New Request from ${req.socket.remoteAddress} for ${req.url}`);
    if(req.url === "/"){
        const form = fs.createReadStream("html/index.html");
        res.writeHead(200, response_headers);
        form.pipe(res);
    }
    else if (req.url.startsWith("/search")){
        const user_input = new URL(req.url, `http://${req.headers.host}`).searchParams;
        const query = user_input.get("query");
        const spreadsheet_id = user_input.get("spreadsheet_id");
        console.log(`Received - query: ${query}, spreadsheet_id: ${spreadsheet_id}`);
        if(!query) {
            res.writeHead(400, response_headers);
            res.end(`<h1>400 Bad Request</h1><p>Query parameter is required.</p>`);
        } else if(!shodan_api_key) {
            res.writeHead(500, response_headers);
            res.end(`<h1>500 Server Error</h1><p>Missing Shodan API key.</p>`);
        } else if(!google_client_id || !google_client_secret) {
            res.writeHead(500, response_headers);
            res.end(`<h1>500 Server Error</h1><p>Missing Google Client ID or Client Secret.</p>`);
        } else {
            const state = crypto.randomBytes(20).toString("hex");
            session.set(state, {query, spreadsheet_id});
            redirect_to_google(state, res);
        }
    }
    else if(req.url.startsWith("/callback")){
        const user_input = new URL(req.url, `http://${req.headers.host}`).searchParams;
        const code = user_input.get("code");
        const state = user_input.get("state");
        if(!code || !state || !session.has(state)){
            res.writeHead(404, response_headers);
            return res.end(`<h1>404 Not Found</h1>`);
        }
        const request_data = session.get(state);
        session.delete(state);
        send_access_token_request(code, request_data, res);
    }
    else{
        res.writeHead(404, response_headers);
        res.end(`<h1>404 Not Found</h1>`);
    }
}

function redirect_to_google(state, res){
    const authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    const uri = querystring.stringify({
        client_id: google_client_id,
        redirect_uri: google_redirect_uri,
        response_type: "code",
        scope: google_scope,
        access_type: "offline",
        state,
        prompt: "select_account",
    });
    res.writeHead(302, {Location: `${authorization_endpoint}?${uri}`}).end();
}

function send_access_token_request(code, request_data, res){
    const token_endpoint = "https://oauth2.googleapis.com/token";
    const post_data = querystring.stringify({
        client_id: google_client_id,
        client_secret: google_client_secret,
        code,
        grant_type: "authorization_code",
        redirect_uri: google_redirect_uri,
    });
    const options = {
        method: "POST",
        headers:{
            "Content-Type":"application/x-www-form-urlencoded",
            "Accept":"application/json",
            "Content-Length": Buffer.byteLength(post_data),
        },
    };
    https.request(
        token_endpoint,
        options,
        (token_stream) => process_http_stream(token_stream, receive_access_token, request_data, res)
    ).end(post_data);
}

// --- Utility Function ---
function process_http_stream(stream, callback, ...args) {
    const {statusCode: status_code} = stream;
    let body = "";
    stream.on("data", function (chunk) {
        body += chunk;
    });
    stream.on("end", () => callback(body, status_code, ...args));
}

function receive_access_token(body, status_code, request_data, res){
    const {access_token} = JSON.parse(body);
    get_shodan_information(request_data, access_token, res);
}

// --- Shodan Service ---
function get_shodan_information(request_data, access_token, res){
    const {query, spreadsheet_id} = request_data;
    request_data.access_token = access_token;
    let shodan_url;
    if(is_ip_address(query)) {
        shodan_url = new URL(`${shodan_host_api_base}${encodeURIComponent(query)}`);
        shodan_url.searchParams.set("key", shodan_api_key);
        request_data.request_type = "host";
    } else {
        shodan_url = new URL(shodan_search_api_base);
        shodan_url.searchParams.set("key", shodan_api_key);
        shodan_url.searchParams.set("query", query);
        request_data.request_type = "search";
    }
    const shodan_req = https.request(shodan_url, {method:"GET", headers:request_headers});
    shodan_req.once("response", (shodan_res) => process_http_stream(shodan_res, parse_shodan_results, request_data, res));
    shodan_req.once("error", (err) => {
        res.writeHead(500, response_headers);
        res.end("<h1>Shodan request failed.</h1>");
    });
    shodan_req.setTimeout(5000, function (){
        shodan_req.destroy();
        res.writeHead(504, response_headers);
        res.end("<h1>Shodan request timed out.</h1>");
    });
    shodan_req.end();  // Sends the Request
}

// --- Parse Results ---
function parse_shodan_results(data, status_code, request_data, res) {
    let response_code = status_code;
    const result_data = {
        query: request_data.query,
        spreadsheet_id: request_data.spreadsheet_id,
        rows: [],
        message: "",
        total: 0,
    };

    if(status_code.toString().startsWith("2")) {
        try {
            const shodan_results = JSON.parse(data);
            if(request_data.request_type === "host") {
                parse_shodan_host_results(shodan_results, request_data, result_data);
            } else {
                parse_shodan_search_results(shodan_results, request_data, result_data);
            }
            response_code = 200;
        }
        catch (err) {
            console.error("JSON parse error:", err);
            result_data.message = "Could not parse Shodan response JSON.";
            response_code = 500;
        }
        if(response_code === 200) {
            return write_results_to_google_sheets(result_data, request_data.access_token, res);
        }
    }
    else if (status_code === 401) {
        response_code = 401;
        result_data.message = "Shodan rejected the API key or denied the request.";
    }
    else if (status_code === 404) {
        if(request_data.request_type === "host") {
            result_data.message = `No Shodan host information was found for ${request_data.query}.`;
        } else {
            result_data.message = "No Shodan endpoint was found for this request.";
        }
    }
    else {
        response_code = 500;
        result_data.message = `Shodan API error (${status_code}).`;
    }
    res.writeHead(response_code, response_headers);
    res.end(`<h1>${result_data.message}</h1>`);
}

function parse_shodan_host_results(shodan_results, request_data, result_data){
    const matches = Array.isArray(shodan_results.data) ? shodan_results.data : [];
    result_data.total = matches.length;
    result_data.rows = matches.map((match) => normalize_shodan_match(match, request_data.query, shodan_results));
    result_data.message = `IP lookup for ${request_data.query}: showing ${result_data.rows.length} of ${result_data.total} indexed service(s).`;
}

function parse_shodan_search_results(shodan_results, request_data, result_data){
    const matches = Array.isArray(shodan_results.matches) ? shodan_results.matches : [];
    result_data.total = typeof shodan_results.total === "number" ? shodan_results.total : 0;
    result_data.rows = matches.slice(0, limit).map((match) => normalize_shodan_match(match, request_data.query));
    result_data.message = `Showing ${result_data.rows.length} of ${result_data.total} Shodan result(s).`;
}

function normalize_shodan_match(match, query, host){
    host = host || {};
    return {
        run_timestamp: new Date().toISOString(),
        timestamp: safe_string(match.timestamp),
        shodan_query: query,
        ip_str: safe_string(match.ip_str || host.ip_str),
        port: safe_string(match.port),
        transport: safe_string(match.transport),
        isp: safe_string(match.isp || host.isp),
        "location.country_name": safe_string((match.location && match.location.country_name) || (host.location && host.location.country_name)),
        "location.city": safe_string((match.location && match.location.city) || (host.location && host.location.city)),
        hostnames: list_or_fallback(match.hostnames, host.hostnames),
        domains: list_or_fallback(match.domains, host.domains),
        product: safe_string(match.product),
        version: safe_string(match.version),
        os: safe_string(match.os || host.os),
        vulns: summarize_vulns(match.vulns || host.vulns),
        ftp: summarize_ftp(match.ftp),
        http: summarize_http(match.http),
        smb: summarize_smb(match.smb),
        ssh: summarize_ssh(match.ssh),
        data: compact_text(match.data, 500),
    };
}

// --- Google Sheets Service ---
function write_results_to_google_sheets(result_data, access_token, res){
    if(result_data.rows.length === 0){
        res.writeHead(404, response_headers);
        return res.end("<h1>No Shodan rows were returned, so no Google Sheet was created or updated.</h1>");
    }
    if(result_data.spreadsheet_id){
        append_rows_to_google_sheet(access_token, result_data, result_data.spreadsheet_id, spreadsheet_url(result_data.spreadsheet_id), false, res);
    }
    else{
        create_google_spreadsheet(access_token, result_data, res);
    }
}

function create_google_spreadsheet(access_token, result_data, res){
    const sheets_endpoint = "https://sheets.googleapis.com/v4/spreadsheets";
    const spreadsheet_data = JSON.stringify({
        properties:{
            title:`CSCI355 Shodan Report ${new Date().toISOString()}`,
        },
    });
    const options = {
        method:"POST",
        headers:{
            "Authorization": `Bearer ${access_token}`,
            "Accept":"application/json",
            "Content-Type":"application/json",
            "Content-Length": Buffer.byteLength(spreadsheet_data),
        },
    };
    https.request(
        sheets_endpoint,
        options,
        (sheets_stream) => process_http_stream(sheets_stream, receive_created_spreadsheet, access_token, result_data, res)
    ).end(spreadsheet_data);
}

function receive_created_spreadsheet(body, status_code, access_token, result_data, res){
    if(!status_code.toString().startsWith("2")){
        res.writeHead(500, response_headers);
        return res.end(`<h1>Google Sheets create request failed (${status_code}).</h1>`);
    }
    try{
        const spreadsheet = JSON.parse(body);
        result_data.spreadsheet_id = spreadsheet.spreadsheetId;
        append_rows_to_google_sheet(access_token, result_data, spreadsheet.spreadsheetId, spreadsheet.spreadsheetUrl, true, res);
    }
    catch(err){
        console.error("Google Sheets JSON parse error:", err);
        res.writeHead(500, response_headers);
        res.end(`<h1>Could not parse Google Sheets create response.</h1>`);
    }
}

function append_rows_to_google_sheet(access_token, result_data, spreadsheet_id, spreadsheet_url_value, include_headers, res){
    const range = encodeURIComponent("Sheet1!A:T");
    const append_endpoint = new URL(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheet_id}/values/${range}:append`);
    append_endpoint.searchParams.set("valueInputOption", "USER_ENTERED");
    const values = result_data.rows.map((row) =>        
        sheet_columns.map((column) => row[column])
    );
    const sheets_data = JSON.stringify({
        values: include_headers ? [sheet_columns].concat(values) : values,
    });
    const options = {
        method:"POST",
        headers:{
            "Authorization": `Bearer ${access_token}`,
            "Accept":"application/json",
            "Content-Type":"application/json",
            "Content-Length": Buffer.byteLength(sheets_data),
        },
    };
    result_data.spreadsheet_url = spreadsheet_url_value;
    https.request(
        append_endpoint,
        options,
        (sheets_stream) => process_http_stream(sheets_stream, receive_appended_rows, result_data, res)
    ).end(sheets_data);
}

function receive_appended_rows(body, status_code, result_data, res){
    if(!status_code.toString().startsWith("2")){
        res.writeHead(500, response_headers);
        return res.end(`<h1>Google Sheets append request failed (${status_code}).</h1>`);
    }
    try{
        JSON.parse(body);
        res.writeHead(302, {Location: result_data.spreadsheet_url}).end();
    }
    catch(err){
        console.error("Google Sheets append JSON parse error:", err);
        res.writeHead(500, response_headers);
        res.end(`<h1>Could not parse Google Sheets append response.</h1>`);
    }
}

function rows_to_sheet_values(rows){
    return rows.map(function(row){
        return sheet_columns.map((column) => row[column]);
    });
}

function spreadsheet_url(spreadsheet_id){
    return `https://docs.google.com/spreadsheets/d/${spreadsheet_id}`;
}

// --- Protocol-Specific Summaries ---
function summarize_ftp(ftp){
    if(!ftp){
        return "N/A";
    }
    const feature_names = object_keys(ftp.features);
    return key_values({
        anonymous: boolean_or_unknown(ftp.anonymous),
        features: feature_names.length ? feature_names.join(", ") : "None listed",
        features_hash: safe_string(ftp.features_hash),
    });
}

function summarize_http(http_data){
    if(!http_data){
        return "N/A";
    }
    return key_values({
        status: safe_string(http_data.status),
        title: safe_string(http_data.title),
        server: safe_string(http_data.server),
        host: safe_string(http_data.host),
        location: safe_string(http_data.location),
        waf: safe_string(http_data.waf),
        components: object_keys(http_data.components).join(", ") || "None listed",
        redirects: Array.isArray(http_data.redirects) ? http_data.redirects.length : "Unknown",
    });
}

function summarize_smb(smb){
    if(!smb){
        return "N/A";
    }
    return key_values({
        anonymous: boolean_or_unknown(smb.anonymous),
        smb_version: safe_string(smb.smb_version),
        software: safe_string(smb.software),
        os: safe_string(smb.os),
        capabilities: comma_separated(smb.capabilities),
        shares: summarize_smb_shares(smb.shares),
    });
}

function summarize_smb_shares(shares){
    if(!Array.isArray(shares) || shares.length === 0){
        return "None listed";
    }
    return shares.map((share) => safe_string(share.name)).join(", ");
}

function summarize_ssh(ssh){
    if(!ssh){
        return "N/A";
    }
    return key_values({
        cipher: safe_string(ssh.cipher),
        mac: safe_string(ssh.mac),
        type: safe_string(ssh.type),
        fingerprint: safe_string(ssh.fingerprint),
        hassh: safe_string(ssh.hassh),
        kex_algorithms: comma_separated(ssh.kex && ssh.kex.kex_algorithms),
        server_host_key_algorithms: comma_separated(ssh.kex && ssh.kex.server_host_key_algorithms),
    });
}

function summarize_vulns(vulns){
    const vuln_names = object_keys(vulns);
    if(vuln_names.length === 0){
        return "None listed";
    }
    return vuln_names.map(function(vuln_name){
        const vuln = vulns[vuln_name];
        const cvss = safe_string(vuln && vuln.cvss);
        const verified = boolean_or_unknown(vuln && vuln.verified);
        return `${vuln_name} (cvss=${cvss}; verified=${verified})`;
    }).join("; ");
}

// --- Helper Functions ---
function is_ip_address(value){
    const parts = value.split(".");
    if(parts.length !== 4){
        return false;
    }
    return parts.every(function(part){
        if(part === "" || !/^\d+$/.test(part)){
            return false;
        }
        const number = Number(part);
        return number >= 0 && number <= 255;
    });
}

function safe_string(value){
    if(value === undefined || value === null || value === ""){
        return "Unknown";
    }
    return String(value);
}

function boolean_or_unknown(value){
    if(typeof value === "boolean"){
        return String(value);
    }
    return "Unknown";
}

function comma_separated(value){
    if(!Array.isArray(value) || value.length === 0){
        return "None listed";
    }
    return value.map(safe_string).join(", ");
}

function list_or_fallback(value, fallback){
    if(Array.isArray(value) && value.length > 0){
        return comma_separated(value);
    }
    return comma_separated(fallback);
}

function object_keys(value){
    if(!value || typeof value !== "object" || Array.isArray(value)){
        return [];
    }
    return Object.keys(value);
}

function key_values(values){
    return Object.keys(values).map((key) => `${key}=${values[key]}`).join("; ");
}

function compact_text(value, max_length){
    if(value === undefined || value === null || value === ""){
        return "Unknown";
    }
    const text = String(value).replace(/\s+/g, " ").trim();
    if(text.length <= max_length){
        return text;
    }
    return `${text.slice(0, max_length)}... [truncated]`;
}
