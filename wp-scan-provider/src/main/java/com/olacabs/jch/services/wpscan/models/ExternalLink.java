package com.olacabs.jch.services.wpscan.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ExternalLink {
    private List<String> id;
    private List<String> url;
    private List<String> cve;
}
