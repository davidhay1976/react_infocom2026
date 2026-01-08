cd ..
ninja -C build/
cd build
sudo ./doca_react -a auxiliary:mlx5_core.sf.4,dv_flow_en=2 -a auxiliary:mlx5_core.sf.2,dv_flow_en=2 --main-lcore 0