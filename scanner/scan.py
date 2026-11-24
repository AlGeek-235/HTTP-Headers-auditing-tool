
# An array listing the security headers to analyse
headers = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
    ]
'''
The below functions are parsing functions used to parse
headers. Each security header has its own parsing function which
returns a dictionnary representing the parsed version, the
returned value is later used for evaluation (by other evaluation functions)

'''

def parse_xfo(value) :
    if (value == "deny" or value == "sameorigin") :
        return{
            "parsed" : {
                "value" : value
            },
            "meta" : {
                "is_secure" : True
            }
        }
    else : 
        return None
    
def parse_xcto(value) :
    if value == "nosniff" :
        return  {
            "parsed" : {
                "value" : value
            },
            "meta" : {
                "is_valid" : True
            }
        }
    else :
        return None
    
def parse_rp(value) : 
    if (
        value == "no-referrer" or 
        value == "strict-origin-when-cross-origin" or
        value == "no-referrer-when-downgrade" or
        value == "origin-when-cross-origin"
       ) :
        return {
            "parsed" : {
                "value" : value
            },
            "meta" : {
                "is_valid" : True
            }
        }
    else :
        return None
def classify_pp_values(value) :
    if value == "*" :
        return "all"
    elif value == "()" or value == "" :
        return "block"
    elif value == "self" :
        return "self-only"
    elif value.startswith("http") or "self" in value:
        return "custom"
    else :
        return "unknown"

def parse_pp(value) :
    if value != None :
            try :
                features = value.split(",")
                parse_feature = {
                    "parse" : {},
                    "meta" : {
                        "total" : 0,
                        "blocked_elts" : [],
                        "elt_with_*_value_list" : [],
                        "total_*_values" : 0 
                    }
                }
                for s in range(len(features)) :
                    features[s] = features[s].strip()
                    features[s] = features[s].split("=")
                
                for elt in range(len(features)) :
                    #building the "parse" section of the dict parse_feature
                    if len(features[elt]) < 2:
                        continue
                    parse_feature["parse"][features[elt][0]] = {}
                    parse_feature["parse"][features[elt][0]]["value"] = features[elt][1]
                    parse_feature["parse"][features[elt][0]]["type"] = classify_pp_values(features[elt][1])
                    parse_feature["meta"]["total"] += 1 
                    #building the "meta" section of the dict parse_feature
                    if classify_pp_values(features[elt][1]) == "all" :
                        parse_feature["meta"]["elt_with_*_value_list"].append(features[elt][0])
                        parse_feature["meta"]["total_*_values"] += 1
                    if classify_pp_values(features[elt][1]) == "block" :
                        parse_feature["meta"]["blocked_elts"].append(features[elt][0])
                return parse_feature
            except Exception as e :
                print(f"[DEBUG] An Error occurs while parsing the permission policy value!")
                return None
    else :
        return None

def parse_hsts(value) :
    if value != None :
        try :
            features = value.split(";")
            parse_features = {
                "parse" : {
                    "max-age" : 0
                },
                "meta" : {
                    "is_valid_age" : False,
                    "is_include-sub-domains_present" : False,
                    "is_preload_present" : False
                }
            }
            max_age = 0
            for s in range(len(features)) :
                features[s] = features[s].strip()
                if("=" in features[s]):
                    features[s] = features[s].split("=")
                if isinstance(features[s], list) and features[s][0] == "max-age" :
                    max_age = int(features[s][1])
            if (max_age >= 31536000) :
                parse_features["meta"]["is_valid_age"] = True
            parse_features["parse"]["max-age"] = max_age
            if "preload" in features :
                parse_features["meta"]["is_preload_present"] = True
            if "includesubdomains" in features :
                parse_features["meta"]["is_include-sub-domains_present"] = True

            return parse_features
        except Exception as e :
            print(f"[DEBUG] An Error occurs while parsing the value of strict transport policy (hsts)!")
            return None

    else :
        return None

def bad_confg_csp_checker(tab):
    if ("'unsafe-inline'" in tab) or ("'unsafe-eval'" in tab):
        return True
    else :
        return False
def parse_csp(value) :
    if value != None :
        try :
            directives = value.split(";")
            directives = [d for d in directives if d.strip()]
            parse_directives = {
                "directives" : {},
                "meta" : {
                    "is_default-src_present" : False,
                    "has_unsafe_values" : False,
                    "total_directives" : 0
                    }
            }
            for d in range(len(directives)) :
                directives[d] = directives[d].strip()
                directives[d] = directives[d].split()

            for d in range(len(directives)) :
                parse_directives["directives"][directives[d][0]] = []
                if "default-src" in parse_directives["directives"].keys():
                    parse_directives["meta"]["is_default-src_present"] = True
                parse_directives["directives"][directives[d][0]].extend(directives[d][1:])
                if bad_confg_csp_checker(parse_directives["directives"][directives[d][0]]) :
                    parse_directives["meta"]["has_unsafe_values"] = True
                parse_directives["meta"]["total_directives"] += 1

            return parse_directives
        except Exception as e :
            print(f"[DEBUG] An Error occurs while parsing the value of content security policy!")
            return None
    else :
        return None

def parsing_orchester(sec_headers):
# A dictionnary for saving parsed versions of the secu headers
    parsed_hd = {
        "content-security-policy": {}, 
        "strict-transport-security": {},
        "x-content-type-options" : {},
        "x-frame-options" : {},
        "referrer-policy" : {},
        "permissions-policy" : {}
    }
    for i in headers :
        match i :
            case "content-security-policy": 
                if ("content-security-policy" in sec_headers.keys()) :
                    parsed_hd["content-security-policy"] = parse_csp(sec_headers["content-security-policy"])
                else :
                    parsed_hd["content-security-policy"] = parse_csp(None)
            case "strict-transport-security":
                if ("strict-transport-security" in sec_headers.keys()) :
                    parsed_hd["strict-transport-security"] = parse_hsts(sec_headers[ "strict-transport-security"])
                else :
                    parsed_hd["strict-transport-security"] = parse_hsts(None)
            case "x-content-type-options" :
                if("x-content-type-options" in sec_headers.keys()) :
                    parsed_hd["x-content-type-options"] = parse_xcto(sec_headers["x-content-type-options"])
                else :
                    parsed_hd["x-content-type-options"] = parse_xcto(None)
            case "x-frame-options" :
                if ("x-frame-options" in sec_headers.keys()) :
                    parsed_hd["x-frame-options"] = parse_xfo(sec_headers["x-frame-options"])
                else :
                    parsed_hd["x-frame-options"] = parse_xfo(None)
            case "referrer-policy" :
                if ("referrer-policy" in sec_headers.keys()) :
                    parsed_hd["referrer-policy"] = parse_rp(sec_headers["referrer-policy"])
                else :
                    parsed_hd["referrer-policy"] = parse_rp(None)
            case "permissions-policy" :
                if ("permissions-policy" in sec_headers.keys()) :
                    parsed_hd["permissions-policy"] = parse_pp(sec_headers["permissions-policy"])
                else :
                    parsed_hd["permissions-policy"] = parse_pp(None)
    return parsed_hd

# evaluation functions
'''
header scores : 
    csp = 30
    hsts = 25
    xfo = 15
    xcto = 10
    rp = 10
    pp = 10
    total = 100
'''
def evaluate_xfo(dic) :
    if dic is None :
        return {
            "status" : "alert",
            "score" : 0,
            "recommandation" : "X-Frame-Options : Either use DENY or SAMEORIGIN as value"
        }
    else :
        return {
            "status" : "OK",
            "score" : 15
        }
    
def evaluate_rp(dic) :
    if dic is None :
        return {
            "status" : "alert",
            "score" : 0,
            "recommandation" : "Referrer Policy : use no-referrer, strict-origin-when-cross-origin or no-referrer-when-downgrade"
        }
    elif (dic["parsed"]["value"] == "origin-when-cross-origin") :
        return {
            "status" : "uncompleted",
            "score" : 5,
            "recommandation" : "Referrer Policy : Use strict-origin-when-cross-origin instead of using origin-when-cross-origin"
        }
    else :
        return {
            "status" : "OK",
            "score" : 10
        }
    
def evaluate_xcto(dic) :
    if dic is None :
        return {
            "status" : "alert",
            "score" : 0,
            "recommandation" : "X-Content-Type-Options: use nosniff as value"
        }
    else :
        return {
            "status" : "OK",
            "score" : 10
        }

def evaluate_pp(dic) :
    if dic == None :
        return {
            "status" : "alert",
            "score" : 0,
            "recommandation" : "Permission Policy is absent, try to add it"
        }
    sensitive = ["geolocation", "camera", "microphone", "usb", "bluetooth", "clipboard-read"]
    blocked = dic["meta"]["blocked_elts"]
    if all(s in blocked for s in sensitive):
        return {
            "status" : "OK",
            "score" : 10
        }
    else :
        return {
            "status" : "alert",
            "score" : 0,
            "recommandation" : "Permission Policy : sensible features like geolocation, camera, microphone, usb, bluetooth, clipboard-read should be blocked!"
        }

def evaluate_hsts(dic) :
    if dic == None or dic == {}:
        return {
            "status" : "alert",
            "score" : 0,
            "recommandation" : "HTTP Strict Transport Security : None of the right values(max-age, include sub domain, preload) is present, add at least one!"
        }
    if (
        dic["meta"]["is_valid_age"] == True and 
        dic["meta"]["is_preload_present"] == True and
        dic["meta"]["is_include-sub-domains_present"] == True
        ) :
        return {
            "status" : "OK",
            "score" : 25
        }
    elif (
        dic["meta"]["is_valid_age"] == True and
        dic["meta"]["is_include-sub-domains_present"] == True
        ) :
        return {
            "status" : "uncompleted",
            "score" : 20,
            "recommandation" : "HTTP Strict Transport Security: Add preload"
        }
    else :
        return {
            "status" : "uncompleted",
            "score" : 10,
            "recommandation" : "HTTP Strict Transport Security (HSTS): Your hsts config values are uncompleted"
        }
    
def evaluate_csp(dic) :
    if dic == None :
        return {
            "status" : "alert",
            "score" : 0,
            "recommandation" : "Content Security Policy (CSP) is absent, add it"
        }
    if (
        dic["meta"]["has_unsafe_values"] == False and 
        dic["meta"]["is_default-src_present"] == True
    ) :
        return {
            "status" : "OK",
            "score" : 30
        }
    elif (
        dic["meta"]["has_unsafe_values"] == False and 
        dic["meta"]["is_default-src_present"] == False
    ) : 
        return {
            "status" : "alert",
            "score" : 15,
            "recommandation" : "Content Security Policy (CSP) : default-src is absent, add it as a fall back value!"
        }
    else :
        return {
            "status" : "alert",
            "score" : 15,
            "recommandation" : "Content Security Policy (CSP) : Don't use unsafe values like unsafe-inline or unsafe-eval"
        }

def evalution_orchester(Sec_Headers):
    parsed_data = parsing_orchester(Sec_Headers)
    result = {
    "Target" : "",
    "Time" : "",
    "Score" : 0,
    "Recommandations" : [],
    "Well_secured_hd" : [],
    "Alert_hd" : [],
    "Level" : ""
    }
    for i in parsed_data :
        match i :
            case "content-security-policy": 
                r = evaluate_csp(parsed_data["content-security-policy"])
                result["Score"] += r["score"]
                if (r["status"] == "OK") :
                    result["Well_secured_hd"].append("content-security-policy")
                else :
                    result["Alert_hd"].append("content-security-policy")
                    result["Recommandations"].append(r["recommandation"])
            case "strict-transport-security":
                r = evaluate_hsts(parsed_data["strict-transport-security"])
                result["Score"] += r["score"]
                if (r["status"] == "OK") :
                    result["Well_secured_hd"].append("strict-transport-security")
                else :
                    result["Alert_hd"].append("strict-transport-security")
                    result["Recommandations"].append(r["recommandation"])
            case "x-content-type-options" :
                r = evaluate_xcto(parsed_data["x-content-type-options"])
                result["Score"] += r["score"]
                if (r["status"] == "OK") :
                    result["Well_secured_hd"].append("x-content-type-options")
                else :
                    result["Alert_hd"].append("x-content-type-options")
                    result["Recommandations"].append(r["recommandation"])
            case "x-frame-options" :
                r = evaluate_xfo(parsed_data["x-frame-options"])
                result["Score"] += r["score"]
                if (r["status"] == "OK") :
                    result["Well_secured_hd"].append("x-frame-options")
                else :
                    result["Alert_hd"].append("x-frame-options")
                    result["Recommandations"].append(r["recommandation"])
            case "referrer-policy" :
                r = evaluate_rp(parsed_data["referrer-policy"])
                result["Score"] += r["score"]
                if (r["status"] == "OK") :
                    result["Well_secured_hd"].append("referrer-policy")
                else :
                    result["Alert_hd"].append("referrer-policy")
                    result["Recommandations"].append(r["recommandation"])
            case "permissions-policy" :
                r = evaluate_pp(parsed_data["permissions-policy"])
                result["Score"] += r["score"]
                if (r["status"] == "OK") :
                    result["Well_secured_hd"].append("permissions-policy")
                else :
                    result["Alert_hd"].append("permissions-policy")
                    result["Recommandations"].append(r["recommandation"])
    if (result["Score"] >= 0 and result["Score"] < 50):
        result["Level"] = "Weak"
    elif (result["Score"] >= 50 and result["Score"] < 70):
        result["Level"] = "Average"
    elif (result["Score"] >= 70 and result["Score"] < 90):
        result["Level"] = "Good"
    else :
        result["Level"] = "Excellent"
    return result