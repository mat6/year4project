//ensures at least one option in form is chosen
//get class of checkboxes, if at least one is checked remove required from all, reapply it if none are checked
function requireCheck(checkboxClass)
{
    var elements = document.getElementsByClassName(checkboxClass);
    var oneChecked = false;
    for(let curElement of elements)
    {
        if(curElement.checked)
        {
            oneChecked = true;
            break;
        }
    }
    for(let curElement of elements)
    {
        curElement.required = !oneChecked;
    }
}