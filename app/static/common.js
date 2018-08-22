"use strict";
function send_certificate_request(domain,cb,cb_fail){
    let form=new FormData();
    form.append('domain',domain);
    return fetch('/cert/get_certificate',{method:'POST',credentials:'same-origin',body:form,headers:{'Accept':'application/json'}})
        .then(cb).catch(cb_fail);
}
function https_request(ev) {
    let elem=$(ev.target);
    let result_elem= elem.parents("td").find("div.result").first();
    result_elem.append('<i class="fa fa-spinner fa-spin"></i>');
    let domain=elem.data('domain');
    let is_on=elem.prop('checked');
    let form=new FormData();
    form.append('domain',domain);form.append('off',is_on?'0':'1');
    function markfailed(){
        result_elem.empty();
        result_elem.append('<i class="fa fa-times"></i>失败');
    }
    function markSuccess(){
        result_elem.empty();
        result_elem.append('<i class="fa fa-check"></i>成功');
        setTimeout(()=>{result_elem.empty()},1000);
    }
    let req_object={method:'POST',credentials:'same-origin',body:form,headers:{'Accept':'application/json'}};
    fetch('/domain/enable_https',req_object)
        .then(res=>{
            if (res.ok){markSuccess();}else{
                if (res.status===403){
                    res.json().then((msgobj)=>{
                        if (msgobj.error.startsWith("No certificate")){
                            result_elem.append('')
                            send_certificate_request(domain,(res)=>{
                                fetch('/domain/enable_https',req_object)
                                    .then(res=>{if (res.ok) markSuccess(); else markfailed();})
                                    .catch(err=>{markfailed()});
                            },()=>{markfailed();})
                        }
                    })
                }else{markfailed()}
            }
        })
        .catch(err=>{markfailed()});
}
function validateEmail(email) {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}
function isValidDomain(v) {
    if (typeof v !== 'string') return false;
    let parts = v.split('.');
    if (parts.length <= 1) return false;
    let tld = parts.pop();
    let tldRegex = /^[a-zA-Z0-9]+$/gi;
    if (!tldRegex.test(tld)) return false;
    return parts.every(function (host) {
        let hostRegex = /^(?!:\/\/)([a-zA-Z0-9]+|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])$/gi;

        return hostRegex.test(host)
    })
}

async function getWhois(domain) {
    let rawResp=await fetch('/whois/'+domain,{headers:{'Accept':'application/json'},credentials:'same-origin'});
    if (rawResp.ok){
        try{
            return await rawResp.json();
        }catch(e){
            return undefined;
        }
    }else{
        return undefined;
    }
}