import { unserialize, serialize } from "php-serialize";
import Redis from "ioredis";
import { createPool } from "mariadb";
import { parse } from "cookie";
import { createDecipheriv } from "crypto";


export class Laravel{
    
    static mariadb_pool = createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USERNAME,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
        database: process.env.DB_DATABASE,
        connectionLimit: 10,
        trace: (process.env.APP_DEBUG == "true"),
        pipelining: true,
    });
    
    static redis = new Redis({
        port: 6379,
        host: "127.0.0.1",
        db: process.env.REDIS_SESSION_DB,
        username: process.env.REDIS_USERNAME,
        password: process.env.REDIS_PASSWORD,
        keyPrefix: process.env.REDIS_PREFIX
    });
    
    // Cookies
    static key = Buffer.from(process.env.APP_KEY.slice(7), "base64");
    static cipher = 'aes-256-cbc';
    static none_encrypted_cookies = [];
    static prefix_len = 41;
    static cookie_fields = ["iv", "value", "mac"];
    static SUPPORTED_CIPHER = {
        "aes-128-cbc": {'size': 16, 'aead': false},
        "aes-256-cbc": {'size': 32, 'aead': false},
        'aes-128-gcm': {'size': 16, 'aead': true},
        'aes-256-gcm': {'size': 32, 'aead': true},
    };
    
    static configs = {
        // session
        session_name: process.env.APP_NAME + "_session",
        session_password: "password_hash_web",
        
        // database
        table_auth: "users",
        table_key: "id",
        table_password: "password"
    }
    
    /**
     * Perform session authentication just like Laravel
     * @param {*} cookies_header 
     * @param {*} idbidder 
     * @returns 
     */
    static async auth(cookies_header, iduser){
        const cookies = this.parse_cookies(cookies_header);
        let mariadb_conn = await this.mariadb_pool.getConnection();
        let query = mariadb_conn.query(`SELECT ${this.configs.table_password} 
                                        FROM ${this.configs.table_auth} 
                                        WHERE ${this.configs.table_key} = ${iduser};`);
        const sessiondata = await this.get_session(cookies[this.configs.session_name]);
        return query.then((rows) => {
            mariadb_conn.release();
            if (rows.length != 1){
                return false;
            }
            if (rows[0][this.configs.table_password] == sessiondata[this.configs.session_password]){
                return true;
            }
            return false;
        });
    }
    
    /**
     * Retrieve session data from id 
     *
     * @param {string} id 
     * @returns {Object} key=>value
     */
    static async get_session(id){
        const session = await this.redis.get(id);
        if (session == null){
            // Session does not exist
            return {};
        }
        return unserialize(unserialize(session));
    }
    
    // Set a field of a session
    static async set_session(id, field, value){
        const session = await this.get_session(id);
        session[field] = value;
        this.redis.set(id, serialize(serialize(session)));
    }
    
    
    // Cookies methods
    /**
     * Parse cookies
     *
     * @param {string} cookies_header 
     * @returns {key => value} 
     */
    static parse_cookies(cookies_header){
        /**
         * cookies {name => encrypted value}
         */
        const encrypred_cookies = parse(cookies_header);
        var cookies = {};
        for (const cookie_name in encrypred_cookies){
            if (this.none_encrypted_cookies.includes(cookie_name)){
                cookies[cookie_name] = encrypred_cookies[cookie_name];
                continue;
            }
            cookies[cookie_name] = this.decrypt_cookie(encrypred_cookies[cookie_name]);
        }
        return cookies;
    }
    
 /**** FROM THIS PART AND BELOW, I LITTERALLY JUST COPY FROM LARAVEL BUT DONT REALLY UNDERSTAND. ****/   
    /**
     * Decrypt cookie
     *
     * Cookies in laravel has the first 41 characters as prefix, so have to remove them.
     * @param {string} encrypred_cookie 
     * @returns 
     */
    static decrypt_cookie(encrypred_cookie){
        // Preprocessing, the payload is a json
        const payload = this.getjson_payload(encrypred_cookie);
        this.is_valid_tag(payload["tag"] === "" ? null : this.base64_decode(payload["tag"]));
        
        // Decryption
        const decipher = createDecipheriv(this.cipher, this.key, Buffer.from(payload["iv"], "base64"));
        if (this.SUPPORTED_CIPHER[this.cipher]["aead"]){
            decipher.setAuthTag(Buffer.from(payload["tag"], "base64"));
        }
        let decrypted_cookie = decipher.update(payload["value"], "base64", "utf-8");
        decrypted_cookie += decipher.final("utf-8");
        
        // The first 41 characters are prefix, remove them.
        return decrypted_cookie.toString("utf-8").slice(this.prefix_len);
    }
    
    /**
     * Retrieve payload in json format
     *
     * This method also involve checking the validity of the payload,
     * throw exception if it is not valid, otherwise return the payload
     *
     * @param {string} encrypred_string 
     * @returns {boolean}
     */
    static getjson_payload(encrypred_string){
        const payload = this.base64_decode(encrypred_string);

        this.cookie_fields.forEach((field) => {
            if (!(field in payload) || !(typeof payload[field] === "string")){
                throw Error(`Invalid payload`);
            }
        });
        
        if (("tag" in payload) && !(typeof payload["tag"] === "string")){
            throw Error("Invalid payload");
        }
        
        return payload;
    }
    
    /**
     * Ensure the given tag match with the cipher
     *
     * Throw exception if the tag doesn't match.
     * @param {string} tag 
     * @return {void}
     */
    static is_valid_tag(tag){
        if (this.SUPPORTED_CIPHER[this.cipher]["aead"] && tag.length != 16){
            throw Error("Could not decrypt the data");
        }
        if (!this.SUPPORTED_CIPHER[this.cipher]["aead"] && (tag instanceof String)){
            throw Error(`Unable to use tag because cipher ${this.cipher} does not support AEAD`);
        }
    }
    
    /**
     * Base64 decoder
     * @param {string} str 
     * @returns 
     */
    static base64_decode(str, encoding="utf-8"){
        const buffer = Buffer.from(str, "base64");
        try {
            return JSON.parse(buffer.toString(encoding));
        }
        catch (error) {
            return buffer.toString(encoding);
        }
    }

}

