package com.olacabs.jch.services.wpscan.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ParsedFinding {
    private String title;
    private String description;
    private String severity;
    private ExternalLink externalLink;
    private String solution;

}
