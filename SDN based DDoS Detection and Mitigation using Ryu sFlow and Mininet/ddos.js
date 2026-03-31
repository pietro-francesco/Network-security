

// --- Settings sFlow-RT ---
var flowkeys = 'ipsource';
var value = 'frames';
var filter = 'outputifindex!=discard&direction=ingress&group:ipsource:ddos=external';
var threshold = 1000; // Pacchetti al secondo per attivare il blocco
var groups = {'external':['0.0.0.0/0'],'internal':['10.0.0.2/32']};

var metricName = 'ddos';
var controls = {};
var enabled = true;
var blockSeconds = 60; // Durata del blocco in secondi

// --- Settings RYU ---
// !! IMPORTANTE: Modifica il dpid con quello del tuo switch !!
var dpid = 1; 
var ryuApiUrl = 'http://127.0.0.1:8080/stats/flowentry/';

// API Ryu
function modifyRyuFlow(action, spec) {
  http(ryuApiUrl + action, 'post', 'application/json', JSON.stringify(spec));
}

// Block IP
function block(address) {
  if(!controls[address]) {
     // JSON flow rules
     var flow = {
         "dpid": dpid,
         "priority": 11, // Priorità alta per scavalcare altre regole
         "match":{
             "dl_type": 2048, // 0x0800 -> Corrisponde a IPv4
             "nw_src": address
         },
         "actions":[] // Una lista di azioni vuota in Ryu significa "DROP"
     };
     
     // Msg add
     modifyRyuFlow('add', flow);
     
     controls[address] = { action:'block', time: (new Date()).getTime() };
     logWarning("Rilevato attacco DDoS - IP di origine: " + address + " -> Inviata regola di blocco a Ryu");
  }
}

// Unblock IP 
function allow(address) {
  if(controls[address]) {
     // Delete flow rule
     var flow = {
         "dpid": dpid,
         "priority": 11,
         "match":{
             "dl_type": 2048,
             "nw_src": address
         }
     };

     // Msg delete
     modifyRyuFlow('delete', flow);

     delete controls[address];
     logInfo("Regola di blocco rimossa per IP: " + address);
  }
}


// --- Events sFlow-RT ---

setEventHandler(function(evt) {
  if(!enabled) return;

  var addr = evt.flowKey;
  block(addr);  
},[metricName]);

setIntervalHandler(function() {
  var stale = [];
  var now = (new Date()).getTime();
  var threshMs = 1000 * blockSeconds;
  for(var addr in controls) {
    if((now - controls[addr].time) > threshMs) stale.push(addr);
  }
  for(var i = 0; i < stale.length; i++) allow(stale[i]);
},10);

setHttpHandler(function(request) {
  var result = {};
  try {
    var action = '' + request.query.action;
    switch(action) {
    case 'block':
       var address = request.query.address[0];
       if(address) block(address);
        break;
    case 'allow':
       var address = request.query.address[0];
       if(address) allow(address);
       break;
    case 'enable':
      enabled = true;
      break;
    case 'disable':
      enabled = false;
      break;
    }
  }
  catch(e) { result.error = e.message }
  result.controls = controls;
  result.enabled = enabled;
  return JSON.stringify(result);
});


// --- Settings sFlow-RT ---

setGroups('ddos',groups);
setFlow(metricName,{keys:flowkeys,value:value,filter:filter});
setThreshold(metricName,{metric:metricName,value:threshold,byFlow:true,timeout:2});
