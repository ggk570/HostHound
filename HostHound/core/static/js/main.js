document.addEventListener("DOMContentLoaded", () => {
    
    // Objects related to specific node
    const EditBtnToEditForm = {
        "workspace": {
            "data-name": "id_name",
            "data-description": "id_description"
        },
        "host": {
            "data-ip-address": "id_ipv4_address",
            "data-hostname": "id_hostname"
        },
        "port": {
            "data-port-no": "id_port_no",
            "data-service": "id_service",
            "data-version": "id_version"
        },
        "endpoint": {
            "data-endpoint-name": "id_endpoint_name",
            "data-status-code": "id_status_code",
            "data-parent": "id_parent"
        },
        "non_workspace": {
            "data-reviewed": "id_reviewed",
            "data-exploitable": "id_exploitable",
            "data-notes": "id_notes"
        }
    };
    const NodeAttributes = (node_name === "workspace") ? EditBtnToEditForm["workspace"] : Object.assign({}, EditBtnToEditForm[node_name], EditBtnToEditForm["non_workspace"]) ;


    // Delete node
    document.querySelectorAll(".delete-btn").forEach(btn => {
        btn.addEventListener("click", (event) => {
            if (!confirm("Are you sure you want to delete this workspace?")) {
                event.preventDefault();
            }
        });
    });

    // Edit node
    const editModal = new bootstrap.Modal(document.getElementById("edit-modal"));
    document.querySelectorAll(".edit-btn").forEach(btn => {
        btn.addEventListener("click", () => {

            document.getElementById("node_id").value = btn.getAttribute("data-id");
            for(const editBtnAttribute in NodeAttributes){
                if(editBtnAttribute == "data-reviewed" || editBtnAttribute == "data-exploitable"){
                    document.getElementById(NodeAttributes[editBtnAttribute]).value = editBtnAttribute.replace("data-", "");
                    document.getElementById(NodeAttributes[editBtnAttribute]).checked = btn.getAttribute(editBtnAttribute) === "True" ? true : false;
                }
                else{
                    if(editBtnAttribute == "data-parent"){
                        let selectTag = document.getElementById('id_parent');
                        for(let option of selectTag.options){
                            if(option.value == btn.getAttribute('data-parent'))
                                option.selected = true;
                        }
                    }
                    else{
                        document.getElementById(NodeAttributes[editBtnAttribute]).value = btn.getAttribute(editBtnAttribute);
                    }
                }
            }
            editModal.show();
        });
    });

    // Handle form submission for editing
    document.getElementById("edit-submit-button").addEventListener("click", event => {
        event.preventDefault();
        const id = document.getElementById("node_id").value;
        const form = document.getElementById("edit-form");
        form.action = `/${node_name}-edit/${id}/`;
        form.submit();
    });
});