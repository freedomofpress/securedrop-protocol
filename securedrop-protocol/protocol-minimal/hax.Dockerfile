ARG HAX_BASE_IMAGE=hax
FROM ${HAX_BASE_IMAGE}
RUN nix profile install nixpkgs#gnumake
