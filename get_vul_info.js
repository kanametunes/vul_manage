function get_vul_info(){
    //NVDからデータ取るときの条件として必要。プロダクトのCPEの値はNISTのサイトで確認 https://nvd.nist.gov/products/cpe/search
    const products = [
        {
        "name":"Chrome",
        "cpe":"cpe:2.3:a:google:chrome:-:*:*:*:*:*:*:*"
        },
        {
        "name":"Firefox",
        "cpe":"cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"
        },
        {
        "name":"macOS -10",
        "cpe":"cpe:2.3:a:apple:mac_os_x:*:*:*:*:*:*:*:*"
        },
        {
        "name":"macOS 11-",
        "cpe":"cpe:2.3:a:apple:macos:*:*:*:*:*:*:*:*"
        },
        {
        "name":"iPhone",
        "cpe":"cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*"
        },
        {
        "name":"Windows",
        "cpe":"cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"
        },
        {
        "name":"1Password",
        "cpe":"cpe:2.3:a:1password:1password:*:*:*:*:*:*:*:*"
        },
        {
        "name":"Zoom",
        "cpe":"cpe:2.3:a:zoom:zoom:*:*:*:*:*:*:*:*"
        }
    ]
    //Severityとかと取得日時の指定。昨日の11:00−今日の10:59まで
    const severity = "CRITICAL";
    const metrics = "AV:N";
    var sdate = new Date();
    sdate.setDate(sdate.getDate()-1);
    sdate = Utilities.formatDate( sdate, 'Asia/Tokyo', 'yyyy-MM-dd');
    const start_time = sdate+"T11:00:00:000 UTC%2B09:00";
    var edate = new Date();
    edate.setDate(edate.getDate()+0);
    edate = Utilities.formatDate( edate , 'Asia/Tokyo', 'yyyy-MM-dd');
    const end_time = edate+"T10:59:59:999 UTC%2B09:00";  

    //ここからがデータ取得
    products.map(function(product){
    let cpe = product.cpe;
    const nvd_url = "https://services.nvd.nist.gov/rest/json/cves/1.0?modStartDate=" + start_time + "&modEndDate=" + end_time + "&cvssV3Metrics="+ metrics +"&cvssV3Severity="+ severity +"&cpeMatchString=" + cpe;
    let responseData = UrlFetchApp.fetch(nvd_url).getContentText();
    let res = JSON.parse(responseData);
    
    res.result.CVE_Items.map(function(item,i){
        message={
            "text": "> <https://nvd.nist.gov/vuln/detail/" + item.cve.CVE_data_meta.ID + "|" + item.cve.CVE_data_meta.ID + ">\n"
            + "*PRODUCT:* " + product.name + "\n"
            +"*SCORE:* " + item.impact.baseMetricV3.cvssV3.baseScore + "\n"
            +"*VECTOR:* " + item.impact.baseMetricV3.cvssV3.vectorString + "\n"
            +"*CWE:* " + item.cve.problemtype.problemtype_data[0].description[0].value + "\n"
            +"*DESCRIPTION:* " + item.cve.description.description_data[0].value 
        }
        console.log(message);
        post_slack(message);
        Utilities.sleep(1000);
    })
    })
}

function post_slack(message){
    //SlackのIncomming Webhook
    const slack_url = "https://hooks.slack.com/services/hoge/hogehoge/hoge";
    let payload = JSON.stringify(message);
    let options =
    {
    "method" : "post",
    "contentType" : "application/json",
    "payload" : payload
    };
    UrlFetchApp.fetch(slack_url, options);
}