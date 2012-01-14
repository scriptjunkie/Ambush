//= require jquery.tools.min.js
$(document).ready(function() {
window.minNameRowElements = 4;
window.triggers = $(".button").overlay({
	fixed: false
});
window.types = ['DONTCARE', 'DWORD', 'DWORDRANGE', 'CSTRING', 'WCSTRING', 'MEM', 'BITMASK', 'BLOB', 'DWORD_NEQ'];
window.existing_sig_id = -1;
var buttons = $("#yesno button").click(function(e) {
	var yes = buttons.index(this) === 0;
	alert("You clicked " + (yes ? "yes" : "no"));
});
$("#prompt form").submit(function(e) {
	triggers.eq(1).overlay().close();
	var input = $("input", this).val();
	alert(input);
	return e.preventDefault();
});

// select all desired input fields and attach tooltips to them
$("#new :text").tooltip({
	position: "center right",
	effect: "fade",
	opacity: 0.8
});

$('#dllSelect').append(new Option('custom', 'custom'));

if(typeof(dlls) != 'undefined')
	$.each(dlls, function(index,dllname) {
	  $('#dllSelect')[0].add(new Option(dllname, dllname, false, false));
	});
//Add a new column to the parameter table
window.addParam = function(myVal, arg) {
	var paramName = 'ParamName';
	if(typeof(myVal) != "undefined" && typeof(myVal['name']) != "undefined"){
		paramName = myVal['name'];
	} else {
		myVal = {};
	}
	var children = $('#namerow').children();
	var currentNum = children.length-minNameRowElements;
	$('<td><textarea style="display:none" id="hidden'+currentNum+'" name="name'+currentNum+'"></textarea><p class="param" id="div'+currentNum+'" contentEditable="true">' + paramName + '</p></td>').insertAfter($(children[children.length - 3]));

	$('<td><select id="sel'+currentNum+'" name="type'+currentNum+'" onchange="typeChange('+currentNum+')"><option value="DWORD">Integer</option><option value="CSTRING">C string</option><option value="WCSTRING">Wide-char string</option><option value="BLOB">Blob</option><option value="MEM">Pointer</option></select></td>').insertAfter($('#typerow').find('td:last'));

	$('<td id="typeval'+currentNum+'"></td>').insertAfter($('#restrictiontyperow').find('td:last'));
	$('<td id="restrictval'+currentNum+'"></td>').insertAfter($('#restrictionrow').find('td:last'));
	$('#sel'+currentNum).val(types[myVal['paramtype']]); //Select the right one
	typeChange(currentNum, arg);
};
$('#addparameter').click(addParam);

//Remove the last relevant column from the parameter table
window.removeParam = function() {
	var children = $('#namerow').children();
	if(children.length <= minNameRowElements)
		return;
	$(children[children.length - 3]).remove();
	$('#parambody').children().each(function(indx,row){
		if(row != $('#namerow')[0])
			$(row).find('td:last').remove();
	})
}
$('#removeparameter').click(removeParam);
addParam();
checkActionSelect();
});
function typeChange(i,arg){
	if(!arg) arg = {argtype: 0};
	var argtype = arg['argtype'];
	var val = $('#sel'+i).val();
	var typeHTML = '<select id="sels'+i+'" name="subtype'+i+'" onchange="subtypeChange('+i+')"><option value="DONTCARE">Ignore</option>';
	if(val == "DWORD"){
		typeHTML += '<option value="DWORD">Equals</option><option value="DWORD_NEQ">Does not equal</option><option value="DWORDRANGE">Range</option><option value="BITMASK">Bitmask</option>';
	}else if(val == "CSTRING" || val == "WCSTRING"){
		typeHTML += '<option value="RegExp"'
			+ (argtype != 0 ? ' selected="selected"' : '' ) 
			+ '>Regular Expression</option>';
	}else if(val == "MEM"){
		typeHTML += '<option value="MEM">Memory Protection</option>';
	}else if(val == "BLOB"){
		typeHTML += '<option value="VAL"'
			+ (arg['val1'] == -1 ? ' selected="selected"' : '' ) 
			+ '>Fixed size</option><option value="ARG"'
			+ (arg['val2'] == 0 ? ' selected="selected"' : '' ) 
			+ '>Size specified in argument</option>';
	}
	$('#typeval'+i).html(typeHTML+'</select>');
	if($('#sels'+i+' option[value='+types[argtype]+']').length > 0)
		$('#sels'+i).val(types[argtype]); //Select the right one
	subtypeChange(i, arg);
}
function subtypeChange(i, arg){
	if(!arg) arg = {};
	var val = $('#sels'+i).val();
	if(val == "DONTCARE"){
		$('#restrictval'+i).html('');
	}else if(val == "BITMASK"){
		$('#restrictval'+i).html('<select name="val'+i+'"><option value="0">Any</option><option value="1">All</option><option value="2">Exact</option><option value="3">None</option></select> <input name="subval'+i+'" value="0x84001" size=10 title="An integer bitmask, which can define a match if ANY, ALL, or NONE of the bits set in the signature are set in the function call, or if only those EXACT bits are set"></input>');
	}else if(val == "DWORD" || val == "DWORD_NEQ"){
		$('#restrictval'+i).html('<input name="val'+i+'" value="0" size=10></input>');
	}else if(val == "DWORDRANGE"){
		$('#restrictval'+i).html('<input name="val'+i+'" value="0" size=10></input>-<input name="subval'+i+'" value="0xFFFFFFFF" size=10></input>');
	}else if(val == "RegExp"){
		$('#restrictval'+i).html('<input name="val'+i+'" value="^.*RegExp$" size=20></input>');
	}else if(val == "MEM"){
		$('#restrictval'+i).html('<input name="val'+i+'" value="0" type="hidden"></input><input type="text" name="subval'+i+'" value="0x40" title="A memory protection constant, like PAGE_EXECUTE_READWRITE or a bitmask of possible memory protection values of the memory pointed to"></input>');
		//Set up the tooltip
		$("input[name=subval"+i+"]").tooltip({ position: "center right", effect: "fade", opacity: 0.8 });
	}else if(val == "VAL"){
		$('#restrictval'+i).html('<input name="val'+i+'" value="^\\x00\\xff*RegExp$" size=20></input> Size:<input name="blobval'+i+'" value="0" size=5></input>');
	}else if(val == "ARG"){
		var html = '<input name="val'+i+'" value="^\\x00\\xff*RegExp$" size=20></input> Size arg:<select id="sels'+i+'" name="blobval'+i+'">';
		for(j=0; j<$('#typerow').children().length - 2; j++)
			if(j != i)
				html += '<option value="'+j+'">'+j+'</option>';
		html += '</select>';
		$('#restrictval'+i).html(html);
	}
	//Load saved values if editing
	if(arg['regExp']){
		$('input[name=val'+i+']').val(arg['regExp']);
		if(arg['argtype'] == 7){ //BLOB
			if(arg['val1'] == -1)
				$('[name=blobval'+i+']').val(arg['val2']);
			else
				$('[name=blobval'+i+']').val(arg['val1']);
		}
	}else if(arg['val1']){
		$('[name=val'+i+']').val(arg['val1']);
		$('input[name=subval'+i+']').val(arg['val2']);
		if(val == "BITMASK")
			$('input[name=subval'+i+']').val("0x"+$(arg['val2'])[0].toString(16));
	}
}
function copyContent () {
	var len = $('#typerow').children().length-1;
	for(i=0;i<len;i++)
		$("#hidden"+i).val($("#div"+i).html());
	//Check if editing
	if(window.existing_sig_id != -1){
		deleteSig(window.existing_sig_id);
		window.existing_sig_id = -1;
	}
	//AJAX submit
	$.post('/actions.json', $('#newform').serialize() + "&authenticity_token=" + encodeURIComponent(AUTH_TOKEN),
		function(data){
			$('#sigtbody').append(data.row);
			numSigs++;
			$('#statsBox').text(numSigs);
		}
	).error(function(data){alert('Error creating signature!');});
	closeOverlay();
	return false;
}
function dllChange(functionName, functionParams, conditionArgs){
	var dllname = $('#dllSelect').val();
	$('#dllCustom').val(dllname);
	$('#decl').text('');
	$.getJSON('/available_dll/show.json?name=' + encodeURIComponent(dllname),
		function(data){
			$('#functionSelect').children().remove();
			$('#functionSelect')[0].add(new Option("custom"));
			window.availableFunctions = {};
			for(i = 0; i < data.length; i++){
				$('#functionSelect')[0].add(new Option(data[i][1]));
				window.availableFunctions[data[i][1]] = data[i][0];
			}
			if(functionName){
				$('#functionSelect').val(functionName);
				$('#functionCustom').val(functionName);
				functionChange(functionParams, conditionArgs);
			}
		});
}
function functionChange(functionParams, conditionArgs){
	//if there is a custom function (edited params) use that
	if(functionParams && functionParams.length > 0){
		funcid = functionParams[0].available_function_id;
	}else{ //use manually-selected one
		var funcname = $('#functionSelect').val();
		$('#functionCustom').val(funcname);
		funcid = window.availableFunctions[funcname];
	}
	$.getJSON('/available_function/' + funcid + '.json',
		function(returned){
			data = returned['params'];
			$('#decl').text(returned['decl']);
			while($('#namerow').children().length > minNameRowElements)
				removeParam();
			for(i = 0; i < data.length; i++)
				addParam(data[i], conditionArgs ? conditionArgs[i] : null);
		});
}
function checkActionSelect(){
	$('[name="act[retval]"]').toggle($('#actionSelect').val() == 'BLOCK');
}
function getCheckedSigs(){
	var ret=[];
	var boxes = $('input[type=checkbox]');
	for(i = 0; i < boxes.length; i++)
		if(boxes[i].checked)
			ret.push(parseInt(boxes[i].id));
	return ret;
}
function deleteSig(id){
	$.ajax({url: '/actions/' + id + '.json',
		type: 'DELETE',
		success: function(returned){
			$($('#'+id+'_box')[0].parentNode.parentNode).remove();
			numSigs--;
			$('#statsBox').text(numSigs);
		},
		data: "authenticity_token=" + encodeURIComponent(AUTH_TOKEN)
	});
}
function deleteSigs(){
	var sigs = getCheckedSigs();
	for(i = 0; i < sigs.length; i++)
		deleteSig(sigs[i]);
	triggers.eq(1).overlay().close();
}
function editAction(){
	checkedSigs = getCheckedSigs();
	if(checkedSigs.length != 1)
		return alert('Check one you want to edit');
	window.existing_sig_id = getCheckedSigs()[0];
	$('#modalTitle').html('Edit signature');
	//Display the overlay
	$('#new').overlay({load:true, fixed: false}).load();
	$.getJSON('/actions/'+getCheckedSigs()[0]+'.json',function(data){
		for(key in data.action)
			$('[name="act['+key+']"]').attr('value', data.action[key]);
		//Get action, severity, and dll
		$('[name="act[action]"]').attr('value', ['ALERT','BLOCK','KILLTHREAD','KILLPROC'][data.action.action]);
		$('#severitySelect').val(data.action.severity);
		$('#dllSelect').val(data.dll);
		if(data.action.retprotectMode == null || data.action.retprotectMode == 0)
			$('[name=retprotectType]').val('DONTCARE');
		else
			$('[name=retprotectType]').val('MEM');
		subtypeChange(-1);
		$('[name=subval-1]').val(data.action.retprotectMode);
		dllChange(data.func, data.params, data.arguments);
		checkActionSelect();
	});
}
function newAction(){
	$('#modalTitle').html('New signature');
	$('#new').overlay({load:true, fixed: false}).load();
	window.existing_sig_id = -1; //we're not editing
}
function closeOverlay(){
	$('#new').overlay().close();
}
function newSigSet(){
	$('#new').overlay({load:true, fixed: false}).load();
	$('[name="signature_set[report]"]').attr('value', document.domain);
	$('[name="signature_set[version]"]').attr('value', 1);
}
function submitNewSig(){
	$.post('/signature_sets/', $('#newform').serialize() + "&authenticity_token=" + encodeURIComponent(AUTH_TOKEN),
		function(data){
			$('#sigtbody').append(data.row);
		}
	).error(function(data){alert('Error creating signature!');});
	closeOverlay();
	return false;
}
function deleteSignatureSet(id){
	if(confirm('Delete this signature set with all associated signatures and alerts?'))
		$.ajax({url: '/signature_sets/' + id + '.json',
			type: 'DELETE',
			success: function(returned){
				$($('#'+id+'_box')[0].parentNode).remove();
			},
			data: "authenticity_token=" + encodeURIComponent(AUTH_TOKEN)
		});
}
function getAdm(id){
	document.location = '/signature_sets/'+id+'/adm?domain='+encodeURIComponent(document.domain);
}
