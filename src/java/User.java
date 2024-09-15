
import javax.faces.bean.ManagedBean;  
import javax.faces.bean.RequestScoped;  
@ManagedBean  
@RequestScoped  
public class User {  
String name;  
  
public String getName() {  
return name;  
}  
public void setName(String name) {  
this.name = name;  
}  
}  