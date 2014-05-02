// static/js/application.js



function add (x, y, P) {
  return (x + y) % P;
}

function multiply (x, y, P) {
  return (x*y) % P;
}


function pow (x, y, P) {
  var accum = x;
  for (var i = 1; i < y; i++) {
    accum = (multiply (accum, x, P)) % P;
  }
  return accum;
}


String.prototype.hashCode = function(){
    var hash = 0, i, char;
    if (this.length == 0) return hash;
    for (i = 0, l = this.length; i < l; i++) {
        char  = this.charCodeAt(i);
        hash  = ((hash<<5)-hash)+char;
        hash |= 0; // Convert to 32bit integer
    }
    return hash;
};

