//= require jquery.tools.min.js
function updateAlerts(){
	$.getJSON('/alerts.json?time='+lastUpdate,function(data){
			for(id in data.remove)
				$('#'+id).remove();
			$('tr').removeClass('new')
			$('#sigtbody').prepend(data.rows);
			lastUpdate = data.lastUpdate;
		}
	);
}
setInterval(updateAlerts,10000);
