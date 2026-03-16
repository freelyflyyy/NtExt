function(add_auto_refactor_headers target_name)
    get_target_property(SOURCES ${target_name} SOURCES)

    set(INCLUDE_DEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/${target_name}/include")
    file(MAKE_DIRECTORY "${INCLUDE_DEST_DIR}")
    
    get_filename_component(ABS_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src" REALPATH)
    
    set(REFRACTORED_HEADERS "")
    
    foreach(HEADER_FILE ${SOURCES})
        if(HEADER_FILE MATCHES "\\.h$" OR HEADER_FILE MATCHES "\\.hpp$")
            
            get_filename_component(ABS_HEADER "${HEADER_FILE}" REALPATH)
            get_filename_component(FILE_NAME_ONLY "${ABS_HEADER}" NAME)

            file(RELATIVE_PATH REL_PATH "${ABS_SRC_DIR}" "${ABS_HEADER}")
            
            set(OUTPUT_FILE "${INCLUDE_DEST_DIR}/${REL_PATH}")
            
            get_filename_component(OUTPUT_DIR "${OUTPUT_FILE}" DIRECTORY)
            file(MAKE_DIRECTORY "${OUTPUT_DIR}")
           
            add_custom_command(OUTPUT "${OUTPUT_FILE}" 
                               COMMAND ${CMAKE_COMMAND} -E copy_if_different
                               "${ABS_HEADER}" "${OUTPUT_FILE}"
                               DEPENDS "${ABS_HEADER}"
                               COMMENT "Physically copying: ${FILE_NAME_ONLY} to include/${target_name}/include/")
            
            list(APPEND REFRACTORED_HEADERS "${OUTPUT_FILE}")
        endif()
    endforeach()
    
    if(REFRACTORED_HEADERS)
        set(AUTO_REFACTOR_HEADERS "REFACTOR_${target_name}_HEADERS")
        
        add_custom_target(${AUTO_REFACTOR_HEADERS} ALL
            DEPENDS ${REFRACTORED_HEADERS}
            COMMENT "All headers for ${target_name} have been physically copied to include/${target_name}/include/."
        )
        
        if(TARGET ${target_name})
            add_dependencies(${target_name} ${AUTO_REFACTOR_HEADERS})

            target_include_directories(${target_name} PUBLIC 
                $<BUILD_INTERFACE:${INCLUDE_DEST_DIR}>
            )
        endif()
    endif()
endfunction()