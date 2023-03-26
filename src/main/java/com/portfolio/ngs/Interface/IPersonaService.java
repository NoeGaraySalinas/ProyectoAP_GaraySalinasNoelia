package com.portfolio.ngs.Interface;

import com.portfolio.ngs.Entity.Persona;
import java.util.List;


public interface IPersonaService {
    //Traer una lista de personas
    public List <Persona> getPersona ();


//Guardar un Objeto de tipo persona
public void savePersona (Persona persona) ;

//Eliminar un objeto buscado por Id
public void deletePersona (Long id);
        
//Buscar Persona por id
public Persona findPersona (Long id);        
}