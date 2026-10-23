"""Web HTTP Header, Cookie, Meta-tag and Body Fingerprinting Detector."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from app_stack_finder.core.interfaces import BaseDetector
from app_stack_finder.core.models import ScanResult, ScanTarget, TechCategory, TechItem
from app_stack_finder.detectors.base import clean_version
from app_stack_finder.services.rule_repository import RuleRepository

SERVER_PATTERNS = [
    (r"nginx(?:/([0-9\.]+))?", "Nginx", TechCategory.WEB_SERVERS, "HTTP and reverse proxy server"),
    (r"apache(?:/([0-9\.]+))?", "Apache HTTP Server", TechCategory.WEB_SERVERS, "Apache web server"),
    (r"cloudflare", "Cloudflare", TechCategory.SECURITY, "Cloudflare CDN / WAF / Reverse Proxy"),
    (r"caddy(?:/([0-9\.]+))?", "Caddy", TechCategory.WEB_SERVERS, "Caddy web server"),
    (r"microsoft-iis(?:/([0-9\.]+))?", "Microsoft IIS", TechCategory.WEB_SERVERS, "Internet Information Services"),
    (r"gunicorn(?:/([0-9\.]+))?", "Gunicorn", TechCategory.WEB_SERVERS, "Python WSGI HTTP Server"),
    (r"uvicorn", "Uvicorn", TechCategory.WEB_SERVERS, "ASGI HTTP Server"),
    (r"litespeed", "LiteSpeed", TechCategory.WEB_SERVERS, "High performance web server"),
    (r"openresty(?:/([0-9\.]+))?", "OpenResty", TechCategory.WEB_SERVERS, "Nginx-based web platform"),
    (r"envoy", "Envoy Proxy", TechCategory.WEB_SERVERS, "Cloud-native high-performance edge/service proxy"),
    (r"traefik(?:/([0-9\.]+))?", "Traefik", TechCategory.WEB_SERVERS, "Modern HTTP reverse proxy"),
    (r"apache-coyote(?:/([0-9\.]+))?|tomcat(?:/([0-9\.]+))?", "Apache Tomcat", TechCategory.WEB_SERVERS, "Java Servlet and JSP container"),
    (r"jetty(?:/([0-9\.]+))?", "Jetty", TechCategory.WEB_SERVERS, "Java HTTP server and Servlet container"),
    (r"wildfly(?:/([0-9\.]+))?", "WildFly", TechCategory.WEB_SERVERS, "Flexible, lightweight Java application server"),
    (r"jboss\s*(?:web)?(?:/([0-9\.]+([a-zA-Z0-9\.\-_]+)?))?", "JBoss Web", TechCategory.WEB_SERVERS, "JBoss Web Server / Application Container"),
    (r"glassfish(?:/([0-9\.]+))?", "GlassFish", TechCategory.WEB_SERVERS, "Java EE reference application server"),
    (r"big-?ip", "F5 BIG-IP", TechCategory.INFRASTRUCTURE, "F5 BIG-IP Application Delivery Controller"),
    (r"f5-trafficshield", "F5 BIG-IP TrafficShield", TechCategory.SECURITY, "F5 Web Application Firewall"),
    (r"citrix", "Citrix NetScaler (ADC)", TechCategory.INFRASTRUCTURE, "Citrix NetScaler ADC / Load Balancer"),
    (r"fortiweb", "Fortinet FortiWeb (WAF)", TechCategory.SECURITY, "Fortinet FortiWeb Web Application Firewall"),
    (r"barracuda", "Barracuda WAF", TechCategory.SECURITY, "Barracuda Web Application Firewall"),
]

POWERED_BY_PATTERNS = [
    (r"express", "Express", TechCategory.FRAMEWORKS, "Node.js web framework"),
    (r"next\.?js(?:/([0-9\.]+))?", "Next.js", TechCategory.FRAMEWORKS, "React Production Framework"),
    (r"php(?:/([0-9\.]+))?", "PHP", TechCategory.LANGUAGES, "PHP Hypertext Preprocessor"),
    (r"asp\.net", "ASP.NET", TechCategory.FRAMEWORKS, "Microsoft .NET Web Platform"),
    (r"servlet(?:/([0-9\.]+))?", "Java Servlet", TechCategory.FRAMEWORKS, "Java Servlet Platform"),
    (r"jboss(?:-as)?(?:/([0-9\.]+([a-zA-Z0-9\.\-_]+)?))?", "JBoss", TechCategory.WEB_SERVERS, "JBoss Application Server"),
    (r"wildfly(?:/([0-9\.]+))?", "WildFly", TechCategory.WEB_SERVERS, "WildFly Application Server"),
    (r"undertow(?:/([0-9\.]+))?", "Undertow", TechCategory.WEB_SERVERS, "Lightweight blocking/non-blocking web server in Java"),
    (r"phusion passenger(?:/([0-9\.]+))?", "Phusion Passenger", TechCategory.WEB_SERVERS, "Web app server for Ruby/Python/Node"),
]

HEADER_SIGNATURES = [
    ("cf-ray", "Cloudflare", TechCategory.SECURITY, "Cloudflare Security & CDN"),
    ("cf-cache-status", "Cloudflare", TechCategory.SECURITY, "Cloudflare Edge Cache"),
    ("x-amz-cf-id", "AWS CloudFront", TechCategory.SECURITY, "Amazon CloudFront CDN"),
    ("x-amz-cf-pop", "AWS CloudFront", TechCategory.SECURITY, "Amazon CloudFront CDN PoP"),
    ("x-azure-ref", "Azure Front Door", TechCategory.SECURITY, "Microsoft Azure CDN / Front Door"),
    ("x-fastly-request-id", "Fastly", TechCategory.SECURITY, "Fastly Edge Cloud Platform"),
    ("x-sucuri-id", "Sucuri", TechCategory.SECURITY, "Sucuri Website Security / WAF"),
    ("x-akamai-transformed", "Akamai", TechCategory.SECURITY, "Akamai Intelligent Edge CDN"),
    ("x-vercel-id", "Vercel", TechCategory.INFRASTRUCTURE, "Vercel Edge Network"),
    ("x-nf-request-id", "Netlify", TechCategory.INFRASTRUCTURE, "Netlify Edge Cloud"),
    ("x-kong-proxy-latency", "Kong Gateway", TechCategory.INFRASTRUCTURE, "Kong API Gateway"),
    ("x-envoy-upstream-service-time", "Envoy Proxy", TechCategory.WEB_SERVERS, "Envoy Service Proxy"),
    ("x-varnish", "Varnish", TechCategory.WEB_SERVERS, "Varnish HTTP Cache Reverse Proxy"),
    ("liferay-portal", "Liferay", TechCategory.FRAMEWORKS, "Liferay Enterprise Portal"),
    ("x-wa-info", "F5 BIG-IP WebAccelerator", TechCategory.INFRASTRUCTURE, "F5 BIG-IP Traffic Acceleration"),
    ("x-cnection", "F5 BIG-IP", TechCategory.INFRASTRUCTURE, "F5 BIG-IP ADC connection header"),
    ("x-iinfo", "Imperva Incapsula (WAF)", TechCategory.SECURITY, "Imperva Incapsula WAF tracking header"),
    ("x-fortigate", "Fortinet FortiGate", TechCategory.SECURITY, "Fortinet Security Gateway"),
]

COOKIE_SIGNATURES = [
    ("phpsessid", "PHP", TechCategory.LANGUAGES, "PHP session cookie"),
    ("jsessionid", "Java", TechCategory.LANGUAGES, "Java EE session cookie"),
    ("csrftoken", "Django", TechCategory.FRAMEWORKS, "Django CSRF protection cookie"),
    ("sessionid", "Django", TechCategory.FRAMEWORKS, "Django user session cookie"),
    ("laravel_session", "Laravel", TechCategory.FRAMEWORKS, "Laravel web session cookie"),
    ("connect.sid", "Express", TechCategory.FRAMEWORKS, "Express.js session cookie"),
    ("asp.net_sessionid", "ASP.NET", TechCategory.FRAMEWORKS, "ASP.NET session cookie"),
    (".aspnetcore.antiforgery", "ASP.NET Core", TechCategory.FRAMEWORKS, "ASP.NET Core antiforgery"),
    
    # Load Balancers & WAFs: F5 Networks, Citrix, Fortinet, Barracuda, Imperva, Radware, AWS
    ("f5_cspm", "F5 BIG-IP", TechCategory.INFRASTRUCTURE, "F5 BIG-IP Client-Side Performance Monitoring & Bot Defense"),
    ("bigipserver", "F5 BIG-IP (LTM)", TechCategory.INFRASTRUCTURE, "F5 BIG-IP Local Traffic Manager persistence"),
    ("ts01", "F5 BIG-IP ASM (WAF)", TechCategory.SECURITY, "F5 BIG-IP Application Security Manager (WAF) cookie"),
    ("ts", "F5 BIG-IP ASM (WAF)", TechCategory.SECURITY, "F5 BIG-IP Application Security Manager (WAF) cookie"),
    ("nsc_", "Citrix NetScaler (ADC)", TechCategory.INFRASTRUCTURE, "Citrix NetScaler Application Delivery Controller"),
    ("citrix_ns_id", "Citrix NetScaler (ADC)", TechCategory.INFRASTRUCTURE, "Citrix NetScaler session cookie"),
    ("fortiwafsid", "Fortinet FortiWeb (WAF)", TechCategory.SECURITY, "Fortinet FortiWeb Web Application Firewall"),
    ("bni__barracuda_lb_cookie", "Barracuda Load Balancer", TechCategory.INFRASTRUCTURE, "Barracuda Load Balancer persistence"),
    ("bnis_", "Barracuda Web Application Firewall (WAF)", TechCategory.SECURITY, "Barracuda WAF cookie"),
    ("barra_counter_session", "Barracuda WAF", TechCategory.SECURITY, "Barracuda Web Application Firewall"),
    ("incap_ses_", "Imperva Incapsula (WAF/CDN)", TechCategory.SECURITY, "Imperva Cloud WAF & DDoS Protection"),
    ("visid_incap_", "Imperva Incapsula (WAF/CDN)", TechCategory.SECURITY, "Imperva Cloud WAF & DDoS Protection"),
    ("ak_bmsc", "Akamai Bot Manager", TechCategory.SECURITY, "Akamai Edge Bot Manager"),
    ("bm_sz", "Akamai Bot Manager", TechCategory.SECURITY, "Akamai Edge Bot Manager"),
    ("x-sl-compstate", "Radware AppWall (WAF)", TechCategory.SECURITY, "Radware Web Application Firewall"),
    ("awsalb", "AWS Application Load Balancer (ALB)", TechCategory.INFRASTRUCTURE, "AWS Elastic Load Balancing cookie"),
    ("awsalbapp", "AWS Application Load Balancer (ALB)", TechCategory.INFRASTRUCTURE, "AWS Application Load Balancer sticky cookie"),
    ("serverid", "HAProxy", TechCategory.WEB_SERVERS, "HAProxy load balancer persistence cookie"),
    ("cf_clearance", "Cloudflare", TechCategory.SECURITY, "Cloudflare bot management clearance"),
    ("__cf_bm", "Cloudflare", TechCategory.SECURITY, "Cloudflare Bot Management cookie"),
    ("lumclientid", "Lumis Experience Platform (LumisXP)", TechCategory.FRAMEWORKS, "LumisXP Enterprise Portal / DXP"),
    ("lumusersessionid", "Lumis Experience Platform (LumisXP)", TechCategory.FRAMEWORKS, "LumisXP Enterprise Portal session"),
]

BODY_META_PATTERNS = [
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([0-9\.]*)["\']', "WordPress", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Hugo\s*([0-9\.]*)["\']', "Hugo", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Gatsby\s*([0-9\.]*)["\']', "Gatsby", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Jekyll\s*v?([0-9\.]*)["\']', "Jekyll", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([0-9\.]*)["\']', "Drupal", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Ghost\s*([0-9\.]*)["\']', "Ghost", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!?\s*([0-9\.]*)["\']', "Joomla", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']LumisXP\s*([0-9\.]*)["\']', "Lumis Experience Platform (LumisXP)", TechCategory.FRAMEWORKS),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Mojarra\s*([0-9\.]*)["\']', "Mojarra (JSF)", TechCategory.FRAMEWORKS),
]

# Padrões para comentários de cabeçalho em arquivos JS estáticos
SCRIPT_HEADER_VERSION_PATTERNS = {
    "jQuery": [
        r"/\*!\s*(?:\*\s*)?jQuery\s+v([0-9\.]+)",
        r"/\*!\s*(?:\*\s*)?jQuery\s+JavaScript\s+Library\s+v([0-9\.]+)",
        r"jQuery(?:\s+JavaScript\s+Library)?\s+v?([0-9\.]+)",
        r"jquery[/-]([0-9\.]+)(?:\.slim|\.min)?\.js",
    ],
    "jQuery UI": [
        r"/\*!\s*jQuery\s+UI[ -]v?([0-9\.]+)",
        r"jQuery\s+UI(?:\s+:[a-zA-Z0-9_\-]+|\s+[a-zA-Z0-9_\-]+)?\s+v?([0-9\.]+)",
        r"jQuery\s+UI\s+v?([0-9\.]+)",
        r"jquery-ui[/-]([0-9\.]+)",
    ],
    "jQuery EasyUI": [
        r"jQuery\s+EasyUI\s+v?([0-9\.]+)",
        r"EasyUI\s+v?([0-9\.]+)",
    ],
    "jQuery Masked Input Plugin": [
        r"Masked\s+Input\s+plugin[ a-zA-Z]*Version:\s*([0-9\.]+)",
        r"maskedinput-([0-9\.]+)",
        r"Version:\s*([0-9\.]+)",
    ],
    "jQuery Print Element Plugin": [
        r"Print\s+Element\s+Plugin\s+v?([0-9\.]+)",
        r"PrintArea\s+v?([0-9\.]+)",
    ],
    "jQuery Mask Plugin": [
        r"jQuery\s+Mask\s+Plugin\s+v?([0-9\.]+)",
        r"jQuery-Mask-Plugin[ a-zA-Z]*v?([0-9\.]+)",
    ],
    "Facebox": [
        r"version:\s*([0-9\.]+)",
        r"Facebox[ a-zA-Z]*v?([0-9\.]+)",
    ],
    "Bootstrap": [
        r"/\*!\s*(?:\*\s*)?Bootstrap\s+v([0-9\.]+)",
        r"Bootstrap\s+v?([0-9\.]+)",
    ],
    "Axios": [
        r"/\*!\s*Axios\s+v?([0-9\.]+)",
        r"axios\s+v?([0-9\.]+)",
    ],
    "Popper.js": [
        r"@version\s+([0-9\.]+)",
        r"popper[/-]([0-9\.]+)",
        r"Popper(?:\.js)?\s+v?([0-9\.]+)",
    ],
    "InfraPHP": [
        r"InfraUtil\.js\?([0-9\.\-_]+)",
        r"infra_js/.*(?:\?v?=|\?)([0-9\.\-_]+)",
    ],
    "eproc (Processo Eletrônico)": [
        r"InfraUtil\.js\?([0-9\.]+)",
        r"infra_js/.*(?:\?v?=|\?)([0-9\.]+)",
    ],
    "PrimeFaces": [
        r"/\*!\s*PrimeFaces[ a-zA-Z]*v?([0-9\.]+)",
        r"PrimeFaces\s+v?([0-9\.]+)",
        r"PrimeFaces\.version\s*=\s*['\"]([0-9\.]+)['\"]",
        r"PrimeFaces\.settings\.version\s*=\s*['\"]([0-9\.]+)['\"]",
    ],
    "RichFaces": [
        r"/\*!\s*RichFaces[ a-zA-Z]*v?([0-9\.]+([a-zA-Z0-9\.\-_]+)?)",
        r"RichFaces\s+v?([0-9\.]+([a-zA-Z0-9\.\-_]+)?)",
        r"RichFaces\.version\s*=\s*['\"]([^'\"]+)['\"]",
    ],
    "Ajax4jsf": [
        r"Ajax4jsf[ a-zA-Z]*v?([0-9\.]+([a-zA-Z0-9\.\-_]+)?)",
        r"a4j[a-zA-Z0-9\-_]*\s+v?([0-9\.]+)",
    ],
    "Prototype.js": [
        r"Prototype=\{Version:\"([0-9\.]+)\"",
        r"Prototype\s+JavaScript\s+framework,\s+version\s+([0-9\.]+)",
    ],
    "Modernizr": [
        r"/\*!\s*Modernizr\s+v?([0-9\.]+)",
        r"Modernizr\s+v?([0-9\.]+)",
    ],
    "Glider.js": [
        r"/\*!\s*Glider\.js\s+v?([0-9\.]+)",
        r"glider(?:-js)?@([0-9\.]+)",
    ],
    "Moment.js": [
        r'(?:moment|\.fn|\w)\.version\s*=\s*["\']([0-9\.]+)["\']',
        r"//! moment\.js\s*\n//! version\s*:\s*([0-9\.]+)",
        r"/\*!\s*version\s*:\s*([0-9\.]+).*momentjs\.com",
        r"moment\.js\s+v?([0-9\.]+)",
        r"moment[/-]([0-9\.]+)",
    ],
    "Lodash": [
        r'(?:\.VERSION|VERSION)\s*=\s*["\']([0-9\.]+)["\']',
        r"Lodash\s+<https://lodash\.com/>[\s\S]*?Version\s+([0-9\.]+)",
        r"/\*!\s*lodash\s+v?([0-9\.]+)",
        r"lodash\s+([0-9\.]+)",
        r"lodash[/-]([0-9\.]+)",
    ],
    "jsTree": [
        r'jstree[a-zA-Z0-9_\.]*=\{version:[\"\']([0-9\.]+)[\"\']',
        r'version:[\"\']([0-9\.]+)[\"\'],defaults:',
        r"/\*!\s*jsTree\s+v?([0-9\.]+)",
        r"jstree[/-]([0-9\.]+)",
    ],
    "Vue.js": [
        r"/\*!\s*Vue\.js\s+v([0-9\.]+)",
        r"Vue\s+v([0-9\.]+)",
    ],
    "React": [
        r"/\*!\s*React\s+v([0-9\.]+)",
        r"React\s+v([0-9\.]+)",
    ],
    "Webpack": [
        r"/\*!\s*webpack\s+v?([0-9\.]+)",
        r"webpack[/-]([0-9\.]+)",
        r"(webpackChunk)[a-zA-Z0-9_\-]+",
        r"(webpackJsonp)",
    ],
}

# Detecção detalhada de Frameworks JS, Java (JSF/PrimeFaces/RichFaces), etc.
BODY_CONTENT_PATTERNS = [
    # Java Server Faces & Component Frameworks
    (
        r'(?:primefaces\.js|PrimeFaces\.settings|ln=primefaces|theme\.css\?ln=primefaces|PrimeFaces\.widget|\.ui-widget\b)',
        "PrimeFaces",
        TechCategory.FRAMEWORKS,
        "PrimeFaces JavaServer Faces UI component suite",
        r'(?:primefaces\.js\?v=([0-9\.]+)|ln=primefaces[a-zA-Z0-9\-_]*&amp;v=([0-9\.]+))'
    ),
    (
        r'(?:/a4j/[gs]/([0-9\._]+[a-zA-Z0-9]*?)(?:/org|\.?org)/richfaces|richfaces\.js|RichFaces\.ajax|org\.richfaces|\brf-[a-z0-9\-]+|richfaces-queue\.js|rich\.css)',
        "RichFaces",
        TechCategory.FRAMEWORKS,
        "RichFaces advanced UI component framework for JSF",
        r'(?:/a4j/[gs]/([0-9\._]+[a-zA-Z0-9]*?)(?:/org|\.?org)/richfaces|richfaces[a-zA-Z0-9\-_]*\.js\?v=([0-9\.]+))'
    ),
    (
        r'(?:/a4j/[gs]/([0-9\._]+[a-zA-Z0-9]*?)(?:/org|\.?org)[\./]ajax4jsf|org\.ajax4jsf|a4j:)',
        "Ajax4jsf",
        TechCategory.FRAMEWORKS,
        "Ajax4jsf Rich Internet Applications framework for JSF",
        r'(?:/a4j/[gs]/([0-9\._]+[a-zA-Z0-9]*?)(?:/org|\.?org)[\./]ajax4jsf|org\.ajax4jsf\s+v?([0-9\.]+))'
    ),
    (
        r'(?:prototype(?:\.min)?\.js|PrototypeScript|Prototype=\{Version:["\']([0-9\.]+)["\']|\bPrototype\.Version\b)',
        "Prototype.js",
        TechCategory.FRAMEWORKS,
        "Prototype JavaScript framework",
        r'Prototype=\{Version:["\']([0-9\.]+)["\']'
    ),
    (
        r'(?:\.seam\b|\.seam\?|org\.jboss\.seam|seam/resource|\bSeam\.Component\b)',
        "JBoss Seam",
        TechCategory.FRAMEWORKS,
        "JBoss Seam Enterprise Java Application Framework",
        None
    ),
    (
        r'jquery\.mask(?:\.min)?\.js',
        "jQuery Mask Plugin",
        TechCategory.FRAMEWORKS,
        "jQuery Mask Plugin by Igor Escobar",
        r'jQuery\s+Mask\s+Plugin\s+v?([0-9\.]+)'
    ),
    (
        r'facebox(?:\.min)?\.(?:js|css)',
        "Facebox",
        TechCategory.FRAMEWORKS,
        "Facebox Facebook-style lightbox for jQuery",
        r'version:\s*([0-9\.]+)'
    ),
    (
        r'(?:jquery\.easyui(?:\.min)?\.js|/easyui/)',
        "jQuery EasyUI",
        TechCategory.FRAMEWORKS,
        "jQuery EasyUI UI components collection for web pages",
        r'jQuery\s+EasyUI\s+([0-9\.]+)'
    ),
    (
        r'jquery\.maskedinput(?:-([0-9\.]+))?(?:\.min)?\.js',
        "jQuery Masked Input Plugin",
        TechCategory.FRAMEWORKS,
        "Masked input plugin for jQuery",
        r'jquery\.maskedinput-([0-9\.]+)|Version:\s*([0-9\.]+)'
    ),
    (
        r'jquery\.printElement(?:\.min)?\.js',
        "jQuery Print Element Plugin",
        TechCategory.FRAMEWORKS,
        "Print Element plugin for jQuery",
        r'Print\s+Element\s+Plugin\s+([0-9\.]+)'
    ),
    (
        r'(?:<script[^>]+id=["\']f5_cspm["\']|f5_cspm\.wait_perf_data|\bf5_p:)',
        "F5 BIG-IP",
        TechCategory.INFRASTRUCTURE,
        "F5 BIG-IP Client-Side Performance Monitoring & Bot Defense",
        None
    ),
    (
        r'JBoss\s*Web(?:/([0-9\.]+([a-zA-Z0-9\.\-_]+)?))?',
        "JBoss Web",
        TechCategory.WEB_SERVERS,
        "JBoss Web Server and Servlet container",
        r'JBoss\s*Web/([0-9\.]+([a-zA-Z0-9\.\-_]+)?)'
    ),
    (
        r'(?:javax\.faces\.ViewState|javax\.faces\.resource|jsf\.js|\/javax\.faces\.resource\/|\.faces\b|\.jsf\b)',
        "JavaServer Faces (JSF)",
        TechCategory.FRAMEWORKS,
        "JavaServer Faces specification for building UI components",
        r'(?:ln=javax\.faces(?:&amp;|&)v=([0-9\.]+)|Mojarra(?:/Facelets)?\s+v?([0-9\.]+)|MyFaces(?:-api)?\s+v?([0-9\.]+)|jsf\.js\?v=([0-9\.]+))'
    ),
    (
        r'(?:<meta[^>]+name=["\']generator["\'][^>]+content=["\']LumisXP|LumisPortal\.js|LumisDoui\.js|LumisPortalForm|\blumis/portal\b|\blumis-theme\b)',
        "Lumis Experience Platform (LumisXP)",
        TechCategory.FRAMEWORKS,
        "LumisXP Enterprise Digital Experience Platform and Portal",
        r'Lumis(?:XP)?\s+v?([0-9\.]+)'
    ),
    (
        r'modernizr(?:-([0-9\.]+))?(?:\.min)?\.js',
        "Modernizr",
        TechCategory.FRAMEWORKS,
        "Modernizr JavaScript library for feature detection",
        r'modernizr[/-]([0-9\.]+)'
    ),
    (
        r'glider(?:-js)?(?:@([0-9\.]+))?(?:\.min)?\.(?:js|css)',
        "Glider.js",
        TechCategory.FRAMEWORKS,
        "Fast, lightweight, dependency-free carousel alternative",
        r'glider(?:-js)?@([0-9\.]+)'
    ),
    (
        r'(?:fancybox(?:\.min)?\.(?:js|css)|#fancybox-wrap|\.fancybox\b)',
        "FancyBox",
        TechCategory.FRAMEWORKS,
        "Tool that offers a nice and elegant way to add zooming functionality",
        r'fancybox[/-]([0-9\.]+)'
    ),
    (
        r'vlibras(?:-plugin)?\.js',
        "VLibras (Acessibilidade Digital)",
        TechCategory.OTHER,
        "Suite de ferramentas para acessibilidade em Língua Brasileira de Sinais",
        None
    ),
    (
        r'fonts\.googleapis\.com/(?:icon\?family=Material\+Icons|css)',
        "Google Fonts / Material Icons",
        TechCategory.OTHER,
        "Google Web Fonts and Material Design Icons",
        None
    ),
    (
        r'(?:vaadinBootstrap\.js|window\.Vaadin|\bv-app\b|\bv-ui\b)',
        "Vaadin",
        TechCategory.FRAMEWORKS,
        "Vaadin Java web application framework",
        r'vaadin(?:Bootstrap)?-([0-9\.]+)\.js'
    ),
    (
        r'(?:icefaces\.js|ice\.window|ice\.event)',
        "ICEfaces",
        TechCategory.FRAMEWORKS,
        "ICEfaces open-source extension for JavaServer Faces",
        None
    ),
    (
        r'(?:gwt\.js|\.cache\.js\b|gwt:property)',
        "Google Web Toolkit (GWT)",
        TechCategory.FRAMEWORKS,
        "GWT open-source set of tools for building complex JS front-ends in Java",
        None
    ),

    # JavaScript Libraries & Frameworks
    (
        r'(?:jquery(?:-([0-9\.]+))?(?:\.slim|\.min)?\.js|window\.jQuery\b|code\.jquery\.com|jquery\/([0-9\.]+)\/jquery|npm\.jquery\b)',
        "jQuery",
        TechCategory.FRAMEWORKS,
        "Fast, small, and feature-rich JavaScript library",
        r'(?:jquery[/-]([0-9\.]+)(?:\.slim|\.min)?\.js|jquery\.min\.js\?v=([0-9\.]+)|jQuery\s+JavaScript\s+Library\s+v?([0-9\.]+))'
    ),
    (
        r'(?:jquery-ui(?:-([0-9\.]+))?(?:\.min)?\.js|jquery-ui\.css|/ui/[0-9\.]+/jquery-ui|npm\.jquery-ui\b|bundle-jquery-ui)',
        "jQuery UI",
        TechCategory.FRAMEWORKS,
        "Curated set of user interface interactions, effects, and widgets built on jQuery",
        r'(?:/ui/([0-9\.]+)/|jquery-ui[/-]([0-9\.]+))'
    ),
    (
        r'/_next/static/|id="__next"',
        "Next.js",
        TechCategory.FRAMEWORKS,
        "React Production Framework",
        None
    ),
    (
        r'/_nuxt/|id="__nuxt"',
        "Nuxt",
        TechCategory.FRAMEWORKS,
        "Vue.js Framework",
        None
    ),
    (
        r'ng-version=["\']([0-9\.]+)["\']',
        "Angular",
        TechCategory.FRAMEWORKS,
        "Angular Modern Web Framework",
        r'ng-version=["\']([0-9\.]+)["\']'
    ),
    (
        r'(?:angular(?:-([0-9\.]+))?(?:\.min)?\.js|\bng-app\b|\bng-controller\b)',
        "AngularJS",
        TechCategory.FRAMEWORKS,
        "AngularJS (1.x) superheroic JavaScript MVW framework",
        r'angular[/-]([0-9\.]+)(?:\.min)?\.js'
    ),
    (
        r'(?:react\.production\.min\.js|data-reactroot|react-dom)',
        "React",
        TechCategory.FRAMEWORKS,
        "React UI Library",
        r'react[/-]([0-9\.]+)'
    ),
    (
        r'(?:data-v-[a-f0-9]+|vue(?:-([0-9\.]+))?(?:\.runtime)?(?:\.min)?\.js)',
        "Vue.js",
        TechCategory.FRAMEWORKS,
        "Vue.js Reactive Frontend Framework",
        r'vue[/-]([0-9\.]+)'
    ),
    (
        r'(?:alpine(?:-([0-9\.]+))?(?:\.min)?\.js|\bx-data\b|\bx-init\b)',
        "Alpine.js",
        TechCategory.FRAMEWORKS,
        "Rugged, minimal tool for composing behavior directly in markup",
        r'alpine[/-]([0-9\.]+)'
    ),
    (
        r'(?:htmx(?:\.org)?(?:@([0-9\.]+))?(?:\.min)?\.js|htmx\.org@[0-9\.]+|\bhx-get\b|\bhx-post\b|\bhx-target\b)',
        "HTMX",
        TechCategory.FRAMEWORKS,
        "High power tools for HTML",
        r'htmx(?:\.org)?[/-@]([0-9\.]+)'
    ),
    (
        r'wp-content/|wp-includes/',
        "WordPress",
        TechCategory.FRAMEWORKS,
        "WordPress CMS",
        None
    ),
    (
        r'(?:bootstrap(?:\.min)?\.(?:css|js)|npm\.bootstrap\b|bundle-bs4)',
        "Bootstrap",
        TechCategory.FRAMEWORKS,
        "Bootstrap CSS & Component Library",
        r'(?<![a-zA-Z0-9_\-])bootstrap[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.(?:js|css)|Bootstrap\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
    ),
    (
        r'(?:moment(?:\.min)?\.js|npm\.moment\b)',
        "Moment.js",
        TechCategory.FRAMEWORKS,
        "JavaScript date and time manipulation library",
        r'moment[/-]([0-9\.]+)'
    ),
    (
        r'(?:lodash(?:\.min)?\.js|npm\.lodash\b)',
        "Lodash",
        TechCategory.FRAMEWORKS,
        "Modern JavaScript utility library delivering modularity, performance & extras",
        r'lodash[/-]([0-9\.]+)'
    ),
    (
        r'tailwindcss',
        "Tailwind CSS",
        TechCategory.FRAMEWORKS,
        "Tailwind CSS Utility Framework",
        None
    ),
    (
        r'(?:infra_js/InfraUtil\.js|INFRA_PATH_JS|divInfraAreaGlobal|InfraCookie\.js|\binfra_js/\b|\binfra_css/\b)',
        "InfraPHP",
        TechCategory.FRAMEWORKS,
        "Framework PHP corporativo para eproc e SEI desenvolvido pelo TRF4",
        r'infra_js/[a-zA-Z0-9_\-]+\.js\?([0-9\.\-_]+)'
    ),
    (
        r'(?::: eproc -|Sistema Eproc|\beprocChunk\b|\bwebpackChunkeproc\b|\bnpm\.trf4\b)',
        "eproc (Processo Eletrônico)",
        TechCategory.FRAMEWORKS,
        "Sistema de Processo Judicial Eletrônico (TRF4 / Tribunais)",
        r'infra_js/[a-zA-Z0-9_\-]+\.js\?([0-9\.]+)'
    ),
    (
        r'(?:webpackChunk|runtime\.[a-f0-9]+\.js|js/dist/runtime)',
        "Webpack",
        TechCategory.FRAMEWORKS,
        "Static module bundler for JavaScript applications",
        None
    ),
    (
        r'(?:axios(?:\.min)?\.js|npm\.axios\.)',
        "Axios",
        TechCategory.FRAMEWORKS,
        "Promise based HTTP client for browser and node.js",
        r'axios[/-]([0-9\.]+)'
    ),
    (
        r'(?:npm\.hotwired|@hotwired/turbo|turbo\.min\.js|\bdata-turbo\b)',
        "Hotwired Turbo",
        TechCategory.FRAMEWORKS,
        "High-performance HTML-over-the-wire frontend framework",
        None
    ),
    (
        r'(?:popper(?:\.min)?\.js|npm\.popper\.js)',
        "Popper.js",
        TechCategory.FRAMEWORKS,
        "Tooltip & popover positioning library",
        r'popper[/-]([0-9\.]+)'
    ),
    (
        r'(?:jstree(?:\.min)?\.js|npm\.jstree)',
        "jsTree",
        TechCategory.FRAMEWORKS,
        "Interactive tree component library for jQuery",
        r'jstree[/-]([0-9\.]+)'
    ),
    (
        r'(?:govbr\.css|brasil\.gov\.br|barra-brasil)',
        "Padrão Digital de Governo (Gov.br)",
        TechCategory.OTHER,
        "Padrão Digital e Design System do Governo Brasileiro",
        None
    ),
]


OS_SERVER_PATTERNS = [
    (r"\b(Ubuntu)\b", "Ubuntu Linux", TechCategory.INFRASTRUCTURE),
    (r"\b(Debian)\b", "Debian Linux", TechCategory.INFRASTRUCTURE),
    (r"\b(CentOS)\b", "CentOS Linux", TechCategory.INFRASTRUCTURE),
    (r"\b(Red Hat(?: Enterprise Linux)?|RHEL)\b", "Red Hat Enterprise Linux", TechCategory.INFRASTRUCTURE),
    (r"\b(Fedora)\b", "Fedora Linux", TechCategory.INFRASTRUCTURE),
    (r"\b(FreeBSD)\b", "FreeBSD", TechCategory.INFRASTRUCTURE),
    (r"\b(Amazon(?: Linux)?)\b", "Amazon Linux", TechCategory.INFRASTRUCTURE),
    (r"\b(Unix)\b", "Unix", TechCategory.INFRASTRUCTURE),
    (r"\b(Win32|Win64|Windows)\b", "Microsoft Windows", TechCategory.INFRASTRUCTURE),
]

IIS_OS_VERSION_MAP = {
    "10.0": "Windows Server 2016/2019/2022",
    "8.5": "Windows Server 2012 R2",
    "8.0": "Windows Server 2012",
    "7.5": "Windows Server 2008 R2",
    "7.0": "Windows Server 2008",
    "6.0": "Windows Server 2003",
}

SCRIPT_NAME_KEYWORDS = {
    "jQuery": ["npm.jquery.", "jquery.min.js", "jquery.js", "/jquery/"],
    "jQuery UI": ["npm.jquery-ui.", "jquery-ui", "jquery.ui", "/ui/"],
    "jQuery EasyUI": ["easyui"],
    "jQuery Masked Input Plugin": ["maskedinput"],
    "jQuery Print Element Plugin": ["printelement"],
    "jQuery Mask Plugin": ["jquery.mask."],
    "Facebox": ["facebox."],
    "Prototype.js": ["prototype", "framework.pack.js", "prototypescript"],
    "Ajax4jsf": ["ajax4jsf", "a4j"],
    "RichFaces": ["richfaces"],
    "PrimeFaces": ["primefaces"],
    "Bootstrap": ["npm.bootstrap.", "bootstrap.bundle", "bootstrap.min.js", "bootstrap.js", "bundle-bs4"],
    "Axios": ["npm.axios.", "axios.min.js", "axios.js"],
    "InfraPHP": ["infrautil", "infracookie"],
    "eproc (Processo Eletrônico)": ["infrautil"],
    "Hotwired Turbo": ["hotwired"],
    "Popper.js": ["npm.popper.js", "popper.min.js", "popper.js"],
    "jsTree": ["npm.jstree", "jstree.min.js", "jstree.js"],
    "Modernizr": ["modernizr"],
    "Glider.js": ["glider"],
    "Moment.js": ["npm.moment.", "moment.min.js", "moment.js"],
    "Lodash": ["npm.lodash.", "lodash.min.js", "lodash.js"],
    "Vue.js": ["vue"],
    "React": ["react"],
    "JavaServer Faces (JSF)": ["jsf"],
    "Webpack": ["runtime.", "runtime~", "runtime-", "shared.", "main."],
}


class HeaderDetector(BaseDetector):
    """Detector de tecnologias em servidores web e endpoints HTTP."""

    @property
    def name(self) -> str:
        return "HeaderDetector"

    @property
    def supports_filesystem(self) -> bool:
        return False

    @property
    def supports_url(self) -> bool:
        return True

    async def detect_url(self, url: str, response_data: Dict[str, Any], client: Any = None) -> List[TechItem]:
        items: List[TechItem] = []
        headers: Dict[str, str] = {k.lower(): str(v) for k, v in response_data.get("headers", {}).items()}
        cookies: Dict[str, str] = {k.lower(): str(v) for k, v in response_data.get("cookies", {}).items()}
        body: str = response_data.get("body", "")

        # 1. Analisa Header "Server"
        server_val = headers.get("server", "")
        if server_val:
            detected_server = False
            for pattern, name, cat, desc in SERVER_PATTERNS:
                m = re.search(pattern, server_val, re.IGNORECASE)
                if m:
                    version = clean_version(m.group(1)) if m.groups() and m.group(1) else None
                    items.append(
                        TechItem(
                            name=name,
                            category=cat,
                            version=version,
                            source=f"HTTP Header: Server ({server_val})",
                            confidence=0.98,
                            description=desc,
                        )
                    )
                    detected_server = True

            # Detecta Sistema Operacional a partir do header Server
            for os_pat, os_name, os_cat in OS_SERVER_PATTERNS:
                if re.search(os_pat, server_val, re.IGNORECASE):
                    items.append(
                        TechItem(
                            name=os_name,
                            category=os_cat,
                            source=f"HTTP Header: Server ({server_val})",
                            confidence=0.95,
                            description=f"{os_name} operating system signature in Server header",
                        )
                    )
                    break

            # Se for IIS, infere a versão do Windows Server
            m_iis = re.search(r"microsoft-iis/([0-9\.]+)", server_val, re.IGNORECASE)
            if m_iis:
                iis_v = m_iis.group(1)
                win_os = IIS_OS_VERSION_MAP.get(iis_v, "Microsoft Windows Server")
                items.append(
                    TechItem(
                        name=win_os,
                        category=TechCategory.INFRASTRUCTURE,
                        source=f"Inferred via Microsoft IIS {iis_v}",
                        confidence=0.9,
                        description="Microsoft Windows Server operating system",
                    )
                )

            # Detecta OpenSSL no header Server
            m_ssl = re.search(r"OpenSSL/([0-9\.]+[a-zA-Z]*)", server_val, re.IGNORECASE)
            if m_ssl:
                items.append(
                    TechItem(
                        name="OpenSSL",
                        category=TechCategory.SECURITY,
                        version=clean_version(m_ssl.group(1)),
                        source=f"HTTP Header: Server ({server_val})",
                        confidence=0.95,
                    )
                )

            if not detected_server and server_val:
                items.append(
                    TechItem(
                        name=server_val.split("/")[0],
                        category=TechCategory.WEB_SERVERS,
                        version=clean_version(server_val.split("/")[1]) if "/" in server_val else None,
                        source=f"HTTP Header: Server ({server_val})",
                        confidence=0.8,
                    )
                )

        # 1.5. Analisa Probe de Erro 404 para Servidores Ocultos (ex: JBoss Web, Tomcat)
        probe_body = response_data.get("probe_404_body", "")
        if probe_body:
            m_jboss = re.search(r"JBoss\s*Web/([0-9\.]+([a-zA-Z0-9\.\-_]+)?)", probe_body, re.IGNORECASE)
            if m_jboss:
                v_jb = clean_version(m_jboss.group(1))
                items.append(
                    TechItem(
                        name="JBoss Web",
                        category=TechCategory.WEB_SERVERS,
                        version=v_jb,
                        source=f"Error 404 Server Banner ({m_jboss.group(0)})",
                        confidence=1.0,
                        description="JBoss Web Server and Servlet Container",
                    )
                )
                jboss_as_ver = None
                if v_jb:
                    if v_jb.startswith(("2.", "3.")):
                        jboss_as_ver = "5.x / EAP 5"
                    elif v_jb.startswith("7."):
                        jboss_as_ver = "7.x / EAP 6"
                    elif v_jb.startswith("1."):
                        jboss_as_ver = "4.x"

                items.append(
                    TechItem(
                        name="JBoss Application Server",
                        category=TechCategory.WEB_SERVERS,
                        version=jboss_as_ver,
                        source=f"Inferred via JBoss Web {v_jb or ''}".strip(),
                        confidence=0.9,
                        description="Red Hat JBoss Enterprise Application Platform",
                    )
                )
            m_tomcat = re.search(r"Apache\s*Tomcat/([0-9\.]+)", probe_body, re.IGNORECASE)
            if m_tomcat:
                items.append(
                    TechItem(
                        name="Apache Tomcat",
                        category=TechCategory.WEB_SERVERS,
                        version=clean_version(m_tomcat.group(1)),
                        source=f"Error 404 Server Banner ({m_tomcat.group(0)})",
                        confidence=1.0,
                        description="Apache Tomcat Servlet Container",
                    )
                )

            if not any(it.name == "Apache HTTP Server" for it in items):
                if re.search(r"<p>The requested URL was not found on this server\.</p>", probe_body, re.IGNORECASE) or \
                   re.search(r"<address>Apache(?:/([0-9\.]+))?", probe_body, re.IGNORECASE):
                    m_ap = re.search(r"<address>Apache(?:/([0-9\.]+))?", probe_body, re.IGNORECASE)
                    ap_ver = clean_version(m_ap.group(1)) if m_ap and m_ap.group(1) else None
                    items.append(
                        TechItem(
                            name="Apache HTTP Server",
                            category=TechCategory.WEB_SERVERS,
                            version=ap_ver,
                            source="HTTP 404 Response Signature (Apache)",
                            confidence=0.85,
                            description="Apache HTTP Server",
                        )
                    )

        # 2. Analisa Header "X-Powered-By"
        powered_val = headers.get("x-powered-by", "")
        if powered_val:
            for pattern, name, cat, desc in POWERED_BY_PATTERNS:
                m = re.search(pattern, powered_val, re.IGNORECASE)
                if m:
                    version = clean_version(m.group(1)) if m.groups() and m.group(1) else None
                    items.append(
                        TechItem(
                            name=name,
                            category=cat,
                            version=version,
                            source=f"HTTP Header: X-Powered-By ({powered_val})",
                            confidence=1.0,
                            description=desc,
                        )
                    )

        # 3. Analisa Headers de WAF / CDN / Gateway
        for hdr_name, tech_name, cat, desc in HEADER_SIGNATURES:
            if hdr_name in headers:
                items.append(
                    TechItem(
                        name=tech_name,
                        category=cat,
                        source=f"HTTP Header: {hdr_name}",
                        confidence=0.95,
                        description=desc,
                    )
                )

        # 4. Analisa Cookies (verificação precisa: exata para session cookies e por prefixo para WAF/LB)
        all_cookie_names = set(cookies.keys())
        set_cookie_raw = headers.get("set-cookie", "").lower()

        PREFIX_COOKIES = {
            "ts", "ts01", "bigipserver", "f5_cspm", "awsalb", "awsalbapp", "nsc_", 
            "citrix_ns_id", "fortiwafsid", "bni__barracuda_lb_cookie", "bnis_", 
            "barra_counter_session", "incap_ses_", "visid_incap_", "ak_bmsc", 
            "bm_sz", "x-sl-compstate", "__cf_bm", "cf_clearance", "lumclientid", 
            "lumusersessionid"
        }

        for cookie_pattern, tech_name, cat, desc in COOKIE_SIGNATURES:
            matched = False
            is_prefix = cookie_pattern.endswith(("_", "-")) or cookie_pattern in PREFIX_COOKIES

            for cname in all_cookie_names:
                if is_prefix:
                    if cname.startswith(cookie_pattern) or cookie_pattern in cname:
                        matched = True
                        break
                else:
                    if cname == cookie_pattern:
                        matched = True
                        break

            if not matched:
                if is_prefix and cookie_pattern in set_cookie_raw:
                    matched = True
                elif not is_prefix and re.search(rf"\b{re.escape(cookie_pattern)}=", set_cookie_raw):
                    matched = True

            if matched:
                items.append(
                    TechItem(
                        name=tech_name,
                        category=cat,
                        source=f"HTTP Cookie: {cookie_pattern}",
                        confidence=0.95,
                        description=desc,
                    )
                )

        # 5. Analisa HTML Body / Meta Tags / Scripts
        if body:
            # Meta tags de Generator
            for pattern, tech_name, cat in BODY_META_PATTERNS:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    ver = clean_version(m.group(1)) if m.groups() and m.group(1) else None
                    items.append(
                        TechItem(
                            name=tech_name,
                            category=cat,
                            version=ver,
                            source="HTML Meta Generator Tag",
                            confidence=1.0,
                            description=f"{tech_name} detected via meta generator",
                        )
                    )

            # Patterns no código HTML / Scripts / Atributos
            for pattern, tech_name, cat, desc, ver_pattern in BODY_CONTENT_PATTERNS:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    ver = None
                    if ver_pattern:
                        vm = re.search(ver_pattern, body, re.IGNORECASE)
                        if vm:
                            for g in vm.groups():
                                if g:
                                    ver = clean_version(g)
                                    break
                    elif m.groups() and m.group(1):
                        ver = clean_version(m.group(1))

                    if tech_name == "Webpack" and not ver:
                        if "webpackchunk" in body.lower():
                            ver = "5"
                        elif "webpackjsonp" in body.lower():
                            ver = "4"

                    items.append(
                        TechItem(
                            name=tech_name,
                            category=cat,
                            version=ver,
                            source="HTML Body DOM / Script Signature",
                            confidence=0.9,
                            description=desc,
                        )
                    )

            # Relações implícitas de tecnologias (ex: PrimeFaces/RichFaces -> JavaServer Faces e Java)
            found_names = {item.name for item in items}
            if "PrimeFaces" in found_names or "RichFaces" in found_names or "ICEfaces" in found_names:
                if "JavaServer Faces (JSF)" not in found_names:
                    items.append(
                        TechItem(
                            name="JavaServer Faces (JSF)",
                            category=TechCategory.FRAMEWORKS,
                            source="Implicit via JSF Component Suite",
                            confidence=0.95,
                            description="JavaServer Faces enterprise web framework",
                        )
                    )
                if "Java" not in found_names:
                    items.append(
                        TechItem(
                            name="Java",
                            category=TechCategory.LANGUAGES,
                            source="Implicit via JSF ecosystem",
                            confidence=0.95,
                            description="Java enterprise platform",
                        )
                    )

            # 6. Inspeção Profunda de Assets (Scripts) para extração de versão a partir dos comentários
            if client:
                script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
                for item in items:
                    if item.version or item.name not in SCRIPT_HEADER_VERSION_PATTERNS:
                        continue

                    patterns = SCRIPT_HEADER_VERSION_PATTERNS[item.name]
                    target_script = None
                    keywords = SCRIPT_NAME_KEYWORDS.get(item.name, [item.name.lower().replace(".js", "").replace(" ", "").replace("-", "")])
                    for s in script_srcs:
                        s_lower = s.lower()
                        if any(kw in s_lower for kw in keywords):
                            target_script = s
                            break

                    if target_script:
                        try:
                            resolved_src = urljoin(url, target_script)
                            # 1. Faz requisição dos primeiros 32KB do script
                            script_resp = await client.get(
                                resolved_src,
                                headers={"Range": "bytes=0-32768"},
                                timeout=4.0,
                            )
                            chunk = script_resp.text
                            # Suporte a arquivos .LICENSE.txt gerados pelo Webpack / Terser
                            m_lic = re.search(r"For license information please see\s+([^\s\*]+\.LICENSE\.txt)", chunk[:2048], re.IGNORECASE)
                            if m_lic:
                                lic_file = m_lic.group(1)
                                try:
                                    lic_url = urljoin(resolved_src, lic_file)
                                    lic_resp = await client.get(lic_url, timeout=3.0)
                                    chunk = lic_resp.text + "\n" + chunk
                                except Exception:
                                    pass

                            matched = False
                            for pat in patterns:
                                vm = re.search(pat, chunk, re.IGNORECASE)
                                if vm:
                                    raw_ver = vm.group(1)
                                    if raw_ver.lower().startswith("webpackchunk"):
                                        item.version = "5"
                                    elif raw_ver.lower().startswith("webpackjsonp"):
                                        item.version = "4"
                                    else:
                                        item.version = clean_version(raw_ver)
                                    item.source = f"{item.source} + Asset ({target_script})"
                                    matched = True
                                    break

                            # 2. Se não encontrou no início, busca no final do script (padrão de exportação UMD do Lodash e Moment)
                            if not matched:
                                try:
                                    tail_resp = await client.get(
                                        resolved_src,
                                        headers={"Range": "bytes=-16384"},
                                        timeout=3.0,
                                    )
                                    chunk_tail = tail_resp.text
                                    for pat in patterns:
                                        vm = re.search(pat, chunk_tail, re.IGNORECASE)
                                        if vm:
                                            raw_ver = vm.group(1)
                                            if raw_ver.lower().startswith("webpackchunk"):
                                                item.version = "5"
                                            elif raw_ver.lower().startswith("webpackjsonp"):
                                                item.version = "4"
                                            else:
                                                item.version = clean_version(raw_ver)
                                            item.source = f"{item.source} + Asset ({target_script})"
                                            break
                                except Exception:
                                    pass
                        except Exception:
                            pass

        # 7. Regras Híbridas (Webanalyze Remoto quando disponível no RuleRepository)
        try:
            rule_repo = RuleRepository.get_instance()
            if rule_repo.has_remote_rules:
                remote_items = rule_repo.match_web_response(url, response_data)
                items.extend(remote_items)
        except Exception:
            pass

        res = ScanResult(target=ScanTarget("url", url), items=items)
        res.deduplicate_and_merge()
        return res.items
