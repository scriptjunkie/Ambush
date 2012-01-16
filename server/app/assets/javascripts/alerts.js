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
if (location.href.indexOf('offset') == -1)
	window.poll = setInterval(updateAlerts,10000);
