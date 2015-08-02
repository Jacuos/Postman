function entropy(){
	var pass = document.getElementById('password').value;
	var n = alphabet(pass);
	var entropy = pass.length*Math.log2(n);
	var output = document.getElementById('entr');
	if (pass ==''){entropy = 0}
	
	if (entropy > 60) {
        output.innerHTML = ' siła hasła: bardzo silne '.concat(entropy);
        output.style.color = '#03A9F4';
	} else if (entropy > 45) {
        output.innerHTML = ' siła hasła: silne '.concat(entropy);
        output.style.color = '#4CAF50';
	} else if (entropy > 30) {
        output.innerHTML = ' siła hasła: przeciętne '.concat(entropy);
        output.style.color = '#8BC34A';
	} else if (entropy > 15) {
        output.innerHTML = ' siła hasła: słabe '.concat(entropy);
        output.style.color = '#FFC107';
	} else {
        output.innerHTML = ' siła hasła: bardzo słabe '.concat(entropy);
        output.style.color = '#F44336';
	}
}

function alphabet(pass){
	var n = 0;
	var litD = false;
	var litM = false;
	var cyfr = false;
	for (var i = 0; i < pass.length; i++) {
		character = pass.charAt(i);
		if (!isNaN(character * 1)){
			cyfr = true;
		}
		else if (character == character.toUpperCase()) {
			litD = true;
		}
		else if (character == character.toLowerCase()){
			litM = true;
		}
	}
	
	if(cyfr){n += 10;}
	if(litM){n += 26;}
	if(litD){n += 26;}
		
	
return n;
}