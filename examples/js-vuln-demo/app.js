const userInput = location.search;
document.getElementById('content').innerHTML = userInput;
eval(userCode);
setTimeout("alert('XSS')", 1000);
const token = Math.random().toString(36);
document.write(userInput);
